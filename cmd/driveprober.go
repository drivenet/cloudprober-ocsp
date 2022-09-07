package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/drivenet/cloudprober-ocsp/ocsp"

	"cloud.google.com/go/compute/metadata"
	"github.com/cloudprober/cloudprober"
	"github.com/cloudprober/cloudprober/config"
	"github.com/cloudprober/cloudprober/probes"
	"github.com/cloudprober/cloudprober/web"
	"github.com/golang/glog"
)

var (
	configFile = flag.String("config_file", "", "Config file")
)

const (
	configMetadataKeyName = "cloudprober_config"
	defaultConfigFile     = "/etc/cloudprober.cfg"
)

func configFileToString(fileName string) string {
	b, err := os.ReadFile(fileName)
	if err != nil {
		glog.Exitf("Failed to read the config file: %v", err)
	}
	return string(b)
}

func getConfig() string {
	if *configFile != "" {
		return configFileToString(*configFile)
	}
	// On GCE first check if there is a config in custom metadata
	// attributes.
	if metadata.OnGCE() {
		if cfg, err := config.ReadFromGCEMetadata(configMetadataKeyName); err != nil {
			glog.Infof("Error reading config from metadata. Err: %v", err)
		} else {
			return cfg
		}
	}
	// If config not found in metadata, check default config on disk
	if _, err := os.Stat(defaultConfigFile); !os.IsNotExist(err) {
		return configFileToString(defaultConfigFile)
	}
	glog.Warningf("Config file %s not found. Using default config.", defaultConfigFile)
	return config.DefaultConfig()
}

func catchSignal(sig chan os.Signal) {
	select {
	case s := <-sig:
		glog.Infof("catch signal: %s", s.String())
		os.Exit(0)
	}
}

func main() {
	flag.Parse()
	sig := make(chan os.Signal, 10)

	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGKILL, syscall.SIGQUIT, syscall.SIGTERM)
	go catchSignal(sig)

	// Register stubby probe type
	probes.RegisterProbeType(
		int(ocsp.E_OcspProbe.TypeDescriptor().Number()),
		func() probes.Probe { return &ocsp.Probe{} },
	)

	err := cloudprober.InitFromConfig(getConfig())
	if err != nil {
		glog.Exitf("Error initializing cloudprober. Err: %v", err)
	}

	// web.Init sets up web UI for cloudprober.
	web.Init()

	cloudprober.Start(context.Background())

	// Wait forever
	select {}
}
