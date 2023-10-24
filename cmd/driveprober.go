package main

import (
	"context"
	"flag"

	"github.com/cloudprober/cloudprober"
	"github.com/cloudprober/cloudprober/logger"
	"github.com/cloudprober/cloudprober/probes"
	"github.com/cloudprober/cloudprober/web"

	"github.com/drivenet/cloudprober-ocsp/ocsp"
)

func main() {
	flag.Parse()

	var log = logger.New()

	// Register stubby probe type
	probes.RegisterProbeType(
		int(ocsp.E_OcspProbe.TypeDescriptor().Number()),
		func() probes.Probe { return &ocsp.Probe{} },
	)

	if err := cloudprober.InitFromConfig(""); err != nil {
		log.Criticalf("Error initializing cloudprober. Err: %v", err)
	}

	// web.Init sets up web UI for cloudprober.
	if err := web.Init(); err != nil {
		log.Criticalf("Error initializing web interface. Err: %v", err)
	}

	cloudprober.Start(context.Background())

	// Wait forever
	select {}
}
