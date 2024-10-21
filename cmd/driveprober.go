package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"syscall"
	"time"

	"github.com/cloudprober/cloudprober"
	"github.com/cloudprober/cloudprober/config"
	"github.com/cloudprober/cloudprober/config/runconfig"
	"github.com/cloudprober/cloudprober/logger"
	"github.com/cloudprober/cloudprober/probes"

	"github.com/drivenet/cloudprober-ocsp/ocsp"
)

var (
	versionFlag      = flag.Bool("version", false, "Print version and exit")
	buildInfoFlag    = flag.Bool("buildinfo", false, "Print build info and exit")
	stopTime         = flag.Duration("stop_time", 0, "How long to wait for cleanup before process exits on SIGINT and SIGTERM")
	cpuprofile       = flag.String("cpuprof", "", "Write cpu profile to file")
	memprofile       = flag.String("memprof", "", "Write heap profile to file")
	configTest       = flag.Bool("configtest", false, "Dry run to test config file")
	dumpConfig       = flag.Bool("dumpconfig", false, "Dump processed config to stdout")
	dumpConfigFormat = flag.String("dumpconfig_fmt", "textpb", "Dump config format (textpb, json, yaml)")
)

// These variables get overwritten by using -ldflags="-X main.<var>=<value?" at
// the build time.
var version string
var buildTimestamp string
var dirty string
var l *logger.Logger

func setupProfiling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	var f *os.File
	if *cpuprofile != "" {
		var err error
		f, err = os.Create(*cpuprofile)
		if err != nil {
			l.Critical(err.Error())
		}
		if err = pprof.StartCPUProfile(f); err != nil {
			l.Criticalf("Could not start CPU profiling: %v", err)
		}
	}
	go func(file *os.File) {
		<-sigChan
		pprof.StopCPUProfile()
		if *cpuprofile != "" {
			if err := file.Close(); err != nil {
				l.Critical(err.Error())
			}
		}
		if *memprofile != "" {
			f, err := os.Create(*memprofile)
			if err != nil {
				l.Critical(err.Error())
			}
			if err = pprof.WriteHeapProfile(f); err != nil {
				l.Critical(err.Error())
			}
			if err := f.Close(); err != nil {
				l.Critical(err.Error())
			}
		}
		os.Exit(1)
	}(f)
}

func main() {
	flag.Parse()

	// Initialize logger after parsing flags.
	l = logger.NewWithAttrs(slog.String("component", "global"))

	if len(flag.Args()) > 0 {
		l.Criticalf("Unexpected non-flag arguments: %v", flag.Args())
	}

	if dirty == "1" {
		version += " (dirty)"
	}

	runconfig.SetVersion(version)
	if buildTimestamp != "" {
		ts, err := strconv.ParseInt(buildTimestamp, 10, 64)
		if err != nil {
			l.Criticalf("Error parsing build timestamp (%s). Err: %v", buildTimestamp, err)
		}
		runconfig.SetBuildTimestamp(time.Unix(ts, 0))
	}

	if *versionFlag {
		fmt.Println(runconfig.Version())
		return
	}

	if *buildInfoFlag {
		fmt.Println(runconfig.Version())
		fmt.Println("Built at: ", runconfig.BuildTimestamp())
		return
	}

	if *dumpConfig {
		out, err := config.DumpConfig(*dumpConfigFormat, nil)
		if err != nil {
			l.Criticalf("Error dumping config. Err: %v", err)
		}
		fmt.Println(string(out))
		return
	}

	if *configTest {
		if err := config.ConfigTest(nil); err != nil {
			l.Criticalf("Config test failed. Err: %v", err)
		}
		return
	}

	setupProfiling()

	// Register stubby probe type
	probes.RegisterProbeType(
		int(ocsp.E_OcspProbe.TypeDescriptor().Number()),
		func() probes.Probe { return &ocsp.Probe{} },
	)

	if err := cloudprober.Init(); err != nil {
		l.Criticalf("Error initializing cloudprober. Err: %v", err)
	}

	// web.Init sets up web UI for cloudprober.
	//if err := web.Init(); err != nil {
	//	l.Criticalf("Error initializing web interface. Err: %v", err)
	//}

	startCtx := context.Background()

	if *stopTime == 0 {
		*stopTime = time.Duration(cloudprober.GetConfig().GetStopTimeSec()) * time.Second
	}

	if *stopTime != 0 {
		// Set up signal handling for the cancelation of the start context.
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		ctx, cancelF := context.WithCancel(startCtx)
		startCtx = ctx

		go func() {
			sig := <-sigs
			l.Warningf("Received signal \"%v\", canceling the start context and waiting for %v before closing", sig, *stopTime)
			cancelF()
			time.Sleep(*stopTime)
			os.Exit(0)
		}()
	}
	cloudprober.Start(startCtx)

	// Wait forever
	select {}
}
