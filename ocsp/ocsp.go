package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/google/cloudprober/logger"
	"github.com/google/cloudprober/metrics"
	"github.com/google/cloudprober/probes/options"
	"github.com/google/cloudprober/targets/endpoint"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort = "443"
)

// Probe holds aggregate information about all probe runs, per-target.
type Probe struct {
	name string
	c    *ProbeConf

	opts *options.Options

	//res map[string]*metrics.EventMetrics // Results by target
	l *logger.Logger

	client *http.Client

	targets []endpoint.Endpoint

	// Run counter, used to decide when to update targets or export
	// stats.
	runCnt int64

	// How often to resolve targets (in probe counts), it's the minimum of
	targetsUpdateInterval time.Duration

	// How often to export metrics (in probe counts), initialized to
	// statsExportInterval / p.opts.Interval. Metrics are exported when
	// (runCnt % statsExportFrequency) == 0
	statsExportFrequency int64

	waitGroup sync.WaitGroup

	// Cancel functions for per-target probe loop
	cancelFuncs map[string]context.CancelFunc

	certs    map[string]*x509.Certificate
	issuers  map[string]*x509.Certificate
	requests map[string][]byte
	sync.Mutex
}

type probeResult struct {
	total, success, timeouts int64
	connEvent                int64
	latency                  metrics.Value
	respCodes                *metrics.Map
	ocspCodes                *metrics.Map
}

type callResult struct {
	HTTPStatusCode int
	OCSPStatusCode int

	spent time.Duration
}

// DefaultTargetsUpdateInterval defines default frequency for target updates.
// Actual targets update interval is:
// max(DefaultTargetsUpdateInterval, probe_interval)
var DefaultTargetsUpdateInterval = 10 * time.Second

// maxGapBetweenTargets defines the maximum gap between probe loops for each
// target. Actual gap is either configured or determined by the probe interval
// and number of targets.
const maxGapBetweenTargets = 1 * time.Second

const (
	maxResponseSizeForMetrics = 128
	targetsUpdateInterval     = 1 * time.Minute
	largeBodyThreshold        = bytes.MinRead // 512.
)

// resolveFunc resolves the given host for the IP version.
// This type is mainly used for testing. For all other cases, a nil function
// should be passed to the httpRequestForTarget function.
type resolveFunc func(host string, ipVer int) (net.IP, error)

// Init initializes the probe with the given params.
func (p *Probe) Init(name string, opts *options.Options) error {
	c, ok := opts.ProbeConf.(*ProbeConf)
	if !ok {
		return fmt.Errorf("not a ocsp probe config")
	}

	p.name = name
	p.opts = opts

	if p.l = opts.Logger; p.l == nil {
		p.l = &logger.Logger{}
	}

	p.c = c

	//p.res = make(map[string]*metrics.EventMetrics)
	p.certs = make(map[string]*x509.Certificate)
	p.issuers = make(map[string]*x509.Certificate)

	dialer := &net.Dialer{
		Timeout: p.opts.Timeout,
	}

	if p.opts.SourceIP != nil {
		dialer.LocalAddr = &net.TCPAddr{
			IP: p.opts.SourceIP,
		}
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dialer.DialContext,
		MaxIdleConns:        256, // http.DefaultTransport.MaxIdleConns: 100.
		TLSHandshakeTimeout: p.opts.Timeout,
	}

	if p.c.GetProxyUrl() != "" {
		url, err := url.Parse(p.c.GetProxyUrl())
		if err != nil {
			return fmt.Errorf("error parsing proxy URL (%s): %v", p.c.GetProxyUrl(), err)
		}
		transport.Proxy = http.ProxyURL(url)
	}

	// Thread-safe
	p.client = &http.Client{
		Transport: transport,
	}

	p.statsExportFrequency = p.opts.StatsExportInterval.Nanoseconds() / p.opts.Interval.Nanoseconds()
	if p.statsExportFrequency == 0 {
		p.statsExportFrequency = 1
	}

	p.targets = p.opts.Targets.ListEndpoints()
	p.cancelFuncs = make(map[string]context.CancelFunc, len(p.targets))

	p.targetsUpdateInterval = DefaultTargetsUpdateInterval

	// There is no point refreshing targets before probe interval.
	if p.targetsUpdateInterval < p.opts.Interval {
		p.targetsUpdateInterval = p.opts.Interval
	}
	p.l.Infof("Targets update interval: %v", p.targetsUpdateInterval)

	return nil
}

// Start starts and runs the probe indefinitely.
func (p *Probe) Start(ctx context.Context, dataChan chan *metrics.EventMetrics) {

	defer p.wait()

	p.updateCertificates()
	p.updateTargetsAndStartProbes(ctx, dataChan)

	// Do more frequent listing of targets until we get a non-zero list of
	// targets.
	for {
		if ctxDone(ctx) {
			return
		}
		if len(p.targets) != 0 {
			break
		}
		p.updateTargetsAndStartProbes(ctx, dataChan)
		time.Sleep(p.opts.Interval)
	}

	targetsUpdateTicker := time.NewTicker(p.targetsUpdateInterval)
	defer targetsUpdateTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-targetsUpdateTicker.C:
			p.updateCertificates()
			p.updateTargetsAndStartProbes(ctx, dataChan)
		}
	}
}

// updateTargetsAndStartProbes refreshes targets and starts probe loop for
// new targets and cancels probe loops for targets that are no longer active.
// Note that this function is not concurrency safe. It is never called
// concurrently by Start().
func (p *Probe) updateTargetsAndStartProbes(ctx context.Context, dataChan chan *metrics.EventMetrics) {
	p.targets = p.opts.Targets.ListEndpoints()

	p.l.Debugf("Probe(%s) got %d targets", p.name, len(p.targets))

	// updatedTargets is used only for logging.
	updatedTargets := make(map[string]string)
	defer func() {
		if len(updatedTargets) > 0 {
			p.l.Infof("Probe(%s) targets updated: %v", p.name, updatedTargets)
		}
	}()

	activeTargets := make(map[string]endpoint.Endpoint)
	for _, target := range p.targets {
		key := target.Key()
		activeTargets[key] = target
	}

	// Stop probing for deleted targets by invoking cancelFunc.
	for targetKey, cancelF := range p.cancelFuncs {
		if _, ok := activeTargets[targetKey]; ok {
			continue
		}
		cancelF()
		updatedTargets[targetKey] = "DELETE"
		delete(p.cancelFuncs, targetKey)
	}

	gapBetweenTargets := p.gapBetweenTargets()
	var startWaitTime time.Duration

	// Start probe loop for new targets.
	for key, target := range activeTargets {
		// This target is already initialized.
		if _, ok := p.cancelFuncs[key]; ok {
			continue
		}
		updatedTargets[key] = "ADD"

		probeCtx, cancelF := context.WithCancel(ctx)
		p.waitGroup.Add(1)

		go func(target endpoint.Endpoint, waitTime time.Duration) {
			defer p.waitGroup.Done()
			// Wait for wait time + some jitter before starting this probe loop.
			time.Sleep(waitTime + time.Duration(rand.Int63n(gapBetweenTargets.Microseconds()/10))*time.Microsecond)
			p.startForTarget(probeCtx, target, dataChan)
		}(target, startWaitTime)

		startWaitTime += gapBetweenTargets

		p.cancelFuncs[key] = cancelF
	}
}

func (p *Probe) newResult() *probeResult {
	var latencyValue metrics.Value
	if p.opts.LatencyDist != nil {
		latencyValue = p.opts.LatencyDist.Clone()
	} else {
		latencyValue = metrics.NewFloat(0)
	}
	return &probeResult{
		latency:   latencyValue,
		respCodes: metrics.NewMap("code", metrics.NewInt(0)),
		ocspCodes: metrics.NewMap("ocsp", metrics.NewInt(0)),
	}
}

func (p *Probe) runProbe(ctx context.Context, target endpoint.Endpoint, requests map[string]*http.Request, results map[string]*probeResult) {
	issuer, ok := p.issuers[target.Key()]
	if !ok {
		return
	}

	if p.c.GetRequestsPerProbe() == 1 {
		//p.oc(req.WithContext(reqCtx), target.Name, result, nil)

		for server, req := range requests {
			var (
				ok     bool
				result *probeResult
			)

			ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
			res, err := ocspProbe(p.client, req.WithContext(ctx), issuer)
			cancel()

			if result, ok = results[server]; !ok {
				results[server] = p.newResult()
				result = results[server]
			}

			result.total++

			if err != nil {
				if isClientTimeout(err) {
					p.l.Warning("Target:", target.Name, ", URL:", req.URL.String(), ", http.doHTTPRequest: timeout error: ", err.Error())
					result.timeouts++
					return
				}
				p.l.Warning("Target:", target.Name, ", URL:", req.URL.String(), ", http.doHTTPRequest: ", err.Error())
				return
			}

			result.success++

			result.respCodes.IncKey(strconv.FormatInt(int64(res.HTTPStatusCode), 10))
			result.ocspCodes.IncKey(strconv.FormatInt(int64(res.OCSPStatusCode), 10))
			result.latency.AddFloat64(res.spent.Seconds() / p.opts.LatencyUnit.Seconds())

		}

		return
	}

	// For multiple requests per probe, we launch a separate goroutine for each
	// HTTP request. We use a mutex to protect access to per-target result object
	// in doHTTPRequest. Note that result object is not accessed concurrently
	// anywhere else -- export of metrics happens when probe is not running.
	//var resultMu sync.Mutex
	//
	//wg := sync.WaitGroup{}
	//for numReq := int32(0); numReq < p.c.GetRequestsPerProbe(); numReq++ {
	//	wg.Add(1)
	//	go func(req *http.Request, targetName string, result *probeResult) {
	//		defer wg.Done()
	//		p.doHTTPRequest(req.WithContext(reqCtx), targetName, result, &resultMu)
	//	}(req, target.Name, result)
	//}
	//wg.Wait()
}

func (p *Probe) startForTarget(ctx context.Context, target endpoint.Endpoint, dataChan chan *metrics.EventMetrics) {
	p.l.Debug("Starting probing for the target ", target.Name)

	// We use this counter to decide when to export stats.
	var runCnt int64

	for _, al := range p.opts.AdditionalLabels {
		al.UpdateForTarget(target.Name, target.Labels)
	}

	requests, err := p.ocspRequestForTarget(target)
	if err != nil {
		p.l.Errorf("cannot create OCSP requests for target %s: %s", target.Name, err.Error())
		return
	}

	results := make(map[string]*probeResult, len(requests))

	ticker := time.NewTicker(p.opts.Interval)
	defer ticker.Stop()

	for ts := range ticker.C {
		// Don't run another probe if context is canceled already.
		if ctxDone(ctx) {
			return
		}

		p.runProbe(ctx, target, requests, results)

		// Export stats if it's the time to do so.
		runCnt++
		if (runCnt % p.statsExportFrequency) == 0 {
			for server, result := range results {
				em := metrics.NewEventMetrics(ts).
					AddMetric("total", metrics.NewInt(result.total)).
					AddMetric("success", metrics.NewInt(result.success)).
					AddMetric("latency", result.latency).
					AddMetric("timeouts", metrics.NewInt(result.timeouts)).
					AddMetric("resp-code", result.respCodes).
					AddMetric("ocsp-code", result.ocspCodes).
					AddLabel("ptype", "ocsp").
					AddLabel("probe", p.name).
					AddLabel("ocsp-server", server).
					AddLabel("dst", target.Name)
				em.LatencyUnit = p.opts.LatencyUnit
				for _, al := range p.opts.AdditionalLabels {
					em.AddLabel(al.KeyValueForTarget(target.Name))
				}
				p.opts.LogMetrics(em)
				dataChan <- em
			}
		}
	}
}

func (p *Probe) gapBetweenTargets() time.Duration {
	interTargetGap := time.Duration(p.c.GetIntervalBetweenTargetsMsec()) * time.Millisecond

	// If not configured by user, determine based on probe interval and number of
	// targets.
	if interTargetGap == 0 {
		// Use 1/10th of the probe interval to spread out target groroutines.
		interTargetGap = p.opts.Interval / time.Duration(10*len(p.targets))
	}

	return interTargetGap
}

// Create OCSP http requests, one per OSCP server specified in certificate
func (p *Probe) ocspRequestForTarget(target endpoint.Endpoint) (map[string]*http.Request, error) {
	p.Lock()
	defer p.Unlock()

	var err error

	cert, ok := p.certs[target.Key()]
	if !ok || cert == nil {
		return nil, fmt.Errorf("no domain certificate for target %s", target.Key())
	}

	if len(cert.OCSPServer) < 1 {
		return nil, fmt.Errorf("no OCSP servers defined for target %s", target.Key())
	}

	issuer := p.issuers[target.Key()]
	if !ok || issuer == nil {
		return nil, fmt.Errorf("no issuer certificate for target %s", target.Key())
	}

	body, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, err
	}

	requests := make(map[string]*http.Request, len(cert.OCSPServer))

	for i := range cert.OCSPServer {
		serverUrl, err := url.Parse(cert.OCSPServer[i])
		if err != nil {
			p.l.Errorf("cannot parse URL for OCSP server: %s", cert.OCSPServer[i])
			continue
		}

		requests[serverUrl.Host], err = http.NewRequest(http.MethodPost, cert.OCSPServer[i], bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}

		requests[serverUrl.Host].Header.Add("Content-Type", "application/ocsp-request")
		requests[serverUrl.Host].Header.Add("Accept", "application/ocsp-response")
		requests[serverUrl.Host].Header.Add("host", serverUrl.Host)
	}

	return requests, nil
}

// замени interface чем-то полезным
func ocspProbe(cli *http.Client, req *http.Request, issuer *x509.Certificate) (*callResult, error) {
	var (
		call = &callResult{
			HTTPStatusCode: 0,
			OCSPStatusCode: ocsp.ServerFailed,
		}
		start = time.Now()
	)

	res, err := cli.Do(req)
	call.spent = time.Since(start)

	if err != nil {
		return call, err
	}

	call.HTTPStatusCode = res.StatusCode

	if res.StatusCode != http.StatusOK {
		return call, fmt.Errorf("something went wrong, returned status %d and message %q",
			res.StatusCode,
			res.Status)
	}

	output, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return call, err
	}

	result, err := ocsp.ParseResponse(output, issuer)
	if err != nil {
		return call, err
	}

	call.OCSPStatusCode = result.Status

	return call, nil
}

//
//func (p *Probe)  ocspProbe(server string, issuer *x509.Certificate, request []byte) (string, error) {
//	var payload []string
//
//	httpRequest, err := http.NewRequest(http.MethodPost, server, bytes.NewBuffer(request))
//	if err != nil {
//		return "", err
//	}
//
//	ocspUrl, err := url.Parse(server)
//	if err != nil {
//		return "", err
//	}
//
//	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
//	httpRequest.Header.Add("Accept", "application/ocsp-response")
//	httpRequest.Header.Add("host", ocspUrl.Host)
//	httpClient := &http.Client{}
//	httpResponse, err := httpClient.Do(httpRequest)
//	if err != nil {
//		return "", err
//	}
//	defer httpResponse.Body.Close()
//	output, err := ioutil.ReadAll(httpResponse.Body)
//	if err != nil {
//		return "", err
//	}
//
//	ocspResponse, err := ocsp.ParseResponse(output, issuer)
//	if err != nil {
//		return "", err
//	}
//
//	payload = append(payload, fmt.Sprintf("ocsp_status %d", ocspResponse.Status))
//
//	return strings.Join(payload, "\n"), nil
//}

//
//// runProbe runs probe for all targets and update EventMetrics.
//func (p *Probe) runProbe(ctx context.Context) {
//	p.targets = endpoint.NamesFromEndpoints(p.opts.Targets.ListEndpoints())
//
//	var wg sync.WaitGroup
//	for _, target := range p.targets {
//		wg.Add(1)
//
//		go func(target string, em *metrics.EventMetrics) {
//			defer wg.Done()
//			em.Metric("total").AddInt64(1)
//			start := time.Now()
//			err := p.runProbeForTarget(ctx, target) // run probe just for a single target
//			if err != nil {
//				p.l.Errorf(err.Error())
//				return
//			}
//			em.Metric("success").AddInt64(1)
//			em.Metric("latency").AddFloat64(time.Now().Sub(start).Seconds() / p.opts.LatencyUnit.Seconds())
//		}(target, p.res[target])
//
//	}
//
//	wg.Wait()
//}
//

func (p *Probe) updateCertificates() {
	p.Lock()
	defer p.Unlock()

	p.l.Debugf("Updating certificates")

	for _, target := range p.opts.Targets.ListEndpoints() {
		cert, err := p.downloadServerCertificate(target.Name)
		if err != nil {
			p.l.Errorf("error downloading server certificate: %s", err.Error())
			return
		}

		if cert == nil {
			return
		}

		p.certs[target.Key()] = cert

		var issuer *x509.Certificate
		for _, issuingCert := range cert.IssuingCertificateURL {
			issuer, err = fetchRemote(issuingCert)
			if err != nil {
				continue
			}
			break
		}

		if issuer == nil {
			p.l.Errorf("error downloading issuer certificate")
			return
		}

		p.issuers[target.Key()] = issuer
	}

}

func (p *Probe) downloadServerCertificate(server string) (*x509.Certificate, error) {

	d := &net.Dialer{
		Timeout: p.opts.Timeout,
	}

	if strings.LastIndex(server, ":") == -1 {
		server += ":" + defaultPort
	}

	conn, err := tls.DialWithDialer(d, "tcp", server, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) < 0 {
		return nil, fmt.Errorf("empty peer certificates: %s", server)
	}

	return certs[0], nil
}

func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	in, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	p, _ := pem.Decode(in)
	if p != nil {
		return helpers.ParseCertificatePEM(in)
	}

	return x509.ParseCertificate(in)
}

// Return true if the underlying error indicates a http.Client timeout.
//
// Use for errors returned from http.Client methods (Get, Post).
func isClientTimeout(err error) bool {
	if uerr, ok := err.(*url.Error); ok {
		if nerr, ok := uerr.Err.(net.Error); ok && nerr.Timeout() {
			return true
		}
	}
	return false
}

func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// wait waits for child go-routines (one per target) to clean up.
func (p *Probe) wait() {
	p.waitGroup.Wait()
}
