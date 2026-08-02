package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/certforge/certforge-connector/internal/connector"
)

// Version is set at build time via -ldflags "-X main.Version=vX.Y.Z"
var Version = "dev"

func main() {
	configPath := flag.String("config", "connector.yaml", "path to connector config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println(Version)
		os.Exit(0)
	}

	cfg, err := connector.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	worker, err := connector.NewWorker(cfg, Version)
	if err != nil {
		log.Fatalf("worker: %v", err)
	}
	worker.Run(ctx)
}
