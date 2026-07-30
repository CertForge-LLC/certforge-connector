package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/certforge/certforge-connector/internal/connector"
)

func main() {
	configPath := flag.String("config", "connector.yaml", "path to connector config file")
	flag.Parse()

	cfg, err := connector.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	worker := connector.NewWorker(cfg)
	worker.Run(ctx)
}
