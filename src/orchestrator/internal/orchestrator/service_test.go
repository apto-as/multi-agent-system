package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/apto-as/tmws/orchestrator/internal/config"
)

func TestNewService_Success(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 50051,
		},
		Discovery: config.DiscoveryConfig{
			Paths: []string{"./testdata"},
		},
		Performance: config.PerformanceConfig{
			DiscoveryTimeoutMs: 100,
		},
	}

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	if svc == nil {
		t.Fatal("Service is nil")
	}
	if svc.dockerClient == nil {
		t.Fatal("Docker client not initialized")
	}
	if svc.Discovery == nil {
		t.Fatal("Discovery engine not initialized")
	}
}

func TestNewService_DockerConnectionFail(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 50052,
		},
		Docker: config.DockerConfig{
			Endpoint: "unix:///nonexistent/docker.sock",
		},
		Discovery: config.DiscoveryConfig{
			Paths: []string{"./testdata"},
		},
	}

	_, err := NewService(cfg)
	if err == nil {
		t.Fatal("Expected error for invalid Docker endpoint")
	}
}

func TestServiceStart_DiscoverySuccess(t *testing.T) {
	// Create testdata directory structure
	// This test requires testdata/ to be set up with valid tool.json files

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 50053,
		},
		Discovery: config.DiscoveryConfig{
			Paths: []string{"./testdata"},
		},
		Performance: config.PerformanceConfig{
			StartupTimeoutMs:   500,
			DiscoveryTimeoutMs: 100,
		},
	}

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start service in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- svc.Start(ctx)
	}()

	// Wait for startup (gRPC server)
	time.Sleep(500 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			t.Errorf("Start failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Service did not shut down in time")
	}
}

func TestServiceStop_GracefulShutdown(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 50054,
		},
		Discovery: config.DiscoveryConfig{
			Paths: []string{"./testdata"},
		},
	}

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	// Simulate running state
	svc.running = true

	// Create a dummy gRPC server to test shutdown
	// (In real scenario, this would be started by Start())

	ctx := context.Background()
	err = svc.Stop(ctx)
	if err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	if svc.running {
		t.Error("Service should not be running after Stop()")
	}
}

func TestInitDockerClient_Success(t *testing.T) {
	cfg := &config.Config{
		Docker: config.DockerConfig{
			// Use default Docker endpoint (works if Docker is running)
		},
	}

	client, err := initDockerClient(cfg)
	if err != nil {
		t.Skipf("Docker not available: %v", err)
	}
	defer client.Close()

	if client == nil {
		t.Fatal("Docker client is nil")
	}
}

func TestInitDockerClient_InvalidEndpoint(t *testing.T) {
	cfg := &config.Config{
		Docker: config.DockerConfig{
			Endpoint: "tcp://invalid-host:9999",
		},
	}

	_, err := initDockerClient(cfg)
	if err == nil {
		t.Fatal("Expected error for invalid Docker endpoint")
	}
}
