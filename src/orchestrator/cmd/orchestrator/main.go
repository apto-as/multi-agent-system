package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apto-as/tmws/orchestrator/internal/config"
	"github.com/apto-as/tmws/orchestrator/internal/orchestrator"
)

const (
	defaultConfigPath = "config/orchestrator.yaml"
	version           = "2.3.0"
)

func main() {
	// CLI flags
	configPath := flag.String("config", defaultConfigPath, "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("TMWS Orchestrator Service v%s\n", version)
		os.Exit(0)
	}

	// Load configuration
	log.Printf("Loading configuration from: %s", *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Performance target: <500ms startup
	startTime := time.Now()

	// Create orchestrator service
	svc, err := orchestrator.NewService(cfg)
	if err != nil {
		log.Fatalf("Failed to create orchestrator: %v", err)
	}

	startupTime := time.Since(startTime).Milliseconds()
	if startupTime > int64(cfg.Performance.StartupTimeoutMs) {
		log.Printf("⚠️  WARNING: Startup time %dms exceeded target %dms",
			startupTime, cfg.Performance.StartupTimeoutMs)
	} else {
		log.Printf("✅ Service initialized in %dms (target: <%dms)",
			startupTime, cfg.Performance.StartupTimeoutMs)
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start service
	errChan := make(chan error, 1)
	go func() {
		if err := svc.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case <-sigChan:
		log.Println("Shutdown signal received, gracefully stopping...")
	case err := <-errChan:
		log.Printf("Service error: %v", err)
	}

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := svc.Stop(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
		os.Exit(1)
	}

	log.Println("Service stopped successfully")
}
