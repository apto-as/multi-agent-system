package orchestrator

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/docker/docker/client"
	"google.golang.org/grpc"

	pb "github.com/apto-as/tmws/orchestrator/api"
	"github.com/apto-as/tmws/orchestrator/internal/config"
)

// Service is the main orchestrator service
type Service struct {
	config       *config.Config
	dockerClient *client.Client
	Discovery    *Discovery // Exported for gRPC server access
	running      bool
	grpcServer   *grpc.Server
}

// NewService creates a new orchestrator service
func NewService(cfg *config.Config) (*Service, error) {
	// Initialize Docker client
	dockerClient, err := initDockerClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("docker client init failed: %w", err)
	}

	// Initialize discovery engine
	discovery := NewDiscovery(cfg.Discovery.Paths)

	return &Service{
		config:       cfg,
		dockerClient: dockerClient,
		Discovery:    discovery,
		running:      false,
		grpcServer:   nil,
	}, nil
}

// Start starts the orchestrator service
func (s *Service) Start(ctx context.Context) error {
	log.Println("🚀 Orchestrator service starting...")
	s.running = true

	// Performance target: <100ms discovery
	discoveryStart := time.Now()

	// Discover tools
	tools, err := s.Discovery.Scan()
	if err != nil {
		return fmt.Errorf("tool discovery failed: %w", err)
	}

	discoveryTime := time.Since(discoveryStart).Milliseconds()
	if discoveryTime > int64(s.config.Performance.DiscoveryTimeoutMs) {
		log.Printf("⚠️  WARNING: Discovery time %dms exceeded target %dms",
			discoveryTime, s.config.Performance.DiscoveryTimeoutMs)
	} else {
		log.Printf("✅ Discovered %d tools in %dms (target: <%dms)",
			len(tools), discoveryTime, s.config.Performance.DiscoveryTimeoutMs)
	}

	// Log discovered tools
	for _, tool := range tools {
		log.Printf("  - %s (v%s) [%s]", tool.Name, tool.Version, tool.Category)
	}

	// Start gRPC server
	if err := s.startGRPCServer(); err != nil {
		return fmt.Errorf("gRPC server start failed: %w", err)
	}

	// TODO: Task 1.3 - Start periodic verification
	// if s.config.Discovery.VerifyTools {
	//     s.startPeriodicVerification(ctx)
	// }

	// Wait for context cancellation
	<-ctx.Done()

	// Graceful shutdown
	return s.Stop(ctx)
}

// Stop gracefully stops the orchestrator service
func (s *Service) Stop(ctx context.Context) error {
	if !s.running {
		return nil
	}

	log.Println("🛑 Orchestrator service stopping...")
	s.running = false

	// Stop gRPC server
	if s.grpcServer != nil {
		log.Println("Stopping gRPC server...")
		s.grpcServer.GracefulStop()
		s.grpcServer = nil
	}

	// Close Docker client
	if s.dockerClient != nil {
		if err := s.dockerClient.Close(); err != nil {
			log.Printf("Warning: Docker client close error: %v", err)
		}
	}

	// TODO: Task 1.3 - Stop verification goroutines

	log.Println("✅ Orchestrator service stopped")
	return nil
}

// startGRPCServer starts the gRPC server
func (s *Service) startGRPCServer() error {
	// Create gRPC server implementation (will be defined in api package)
	// For now, create a basic server
	apiServer := &grpcServiceImpl{service: s}

	// Create gRPC server with options
	s.grpcServer = grpc.NewServer()
	pb.RegisterOrchestratorServiceServer(s.grpcServer, apiServer)

	// Build server address from config
	serverAddr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)

	// Start listening
	lis, err := net.Listen("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", serverAddr, err)
	}

	// Start server in goroutine
	go func() {
		log.Printf("🌐 gRPC server listening on %s", serverAddr)
		if err := s.grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server error: %v", err)
		}
	}()

	return nil
}

// grpcServiceImpl is a minimal gRPC service implementation
// Full implementation is in internal/api/server.go
type grpcServiceImpl struct {
	pb.UnimplementedOrchestratorServiceServer
	service *Service
}

func (g *grpcServiceImpl) DiscoverTools(ctx context.Context, req *pb.DiscoverToolsRequest) (*pb.DiscoverToolsResponse, error) {
	tools, err := g.service.Discovery.ScanWithValidation()
	if err != nil {
		return nil, err
	}

	protoTools := make([]*pb.Tool, 0, len(tools))
	for _, tool := range tools {
		protoTools = append(protoTools, &pb.Tool{
			ToolId:     tool.ID,
			Name:       tool.Name,
			Category:   tool.Category,
			SourcePath: tool.SourcePath,
			Version:    tool.Version,
			Metadata:   tool.Metadata,
		})
	}

	return &pb.DiscoverToolsResponse{
		Tools:      protoTools,
		TotalCount: int32(len(tools)),
	}, nil
}

func (g *grpcServiceImpl) GetTool(ctx context.Context, req *pb.GetToolRequest) (*pb.Tool, error) {
	tools, err := g.service.Discovery.Scan()
	if err != nil {
		return nil, err
	}

	for _, tool := range tools {
		if tool.ID == req.ToolId {
			return &pb.Tool{
				ToolId:     tool.ID,
				Name:       tool.Name,
				Category:   tool.Category,
				SourcePath: tool.SourcePath,
				Version:    tool.Version,
				Metadata:   tool.Metadata,
			}, nil
		}
	}

	return nil, fmt.Errorf("tool not found: %s", req.ToolId)
}

func (g *grpcServiceImpl) ListTools(ctx context.Context, req *pb.ListToolsRequest) (*pb.ListToolsResponse, error) {
	tools, err := g.service.Discovery.ScanWithValidation()
	if err != nil {
		return nil, err
	}

	var filteredTools []*Tool
	if req.Category != "" {
		for _, tool := range tools {
			if tool.Category == req.Category {
				filteredTools = append(filteredTools, tool)
			}
		}
	} else {
		filteredTools = tools
	}

	protoTools := make([]*pb.Tool, 0, len(filteredTools))
	for _, tool := range filteredTools {
		protoTools = append(protoTools, &pb.Tool{
			ToolId:     tool.ID,
			Name:       tool.Name,
			Category:   tool.Category,
			SourcePath: tool.SourcePath,
			Version:    tool.Version,
			Metadata:   tool.Metadata,
		})
	}

	return &pb.ListToolsResponse{
		Tools: protoTools,
	}, nil
}

func (g *grpcServiceImpl) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*pb.ContainerInstance, error) {
	return nil, fmt.Errorf("not implemented")
}

func (g *grpcServiceImpl) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*pb.StopContainerResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (g *grpcServiceImpl) GetContainerStatus(ctx context.Context, req *pb.GetContainerStatusRequest) (*pb.ContainerStatus, error) {
	return nil, fmt.Errorf("not implemented")
}

// initDockerClient initializes the Docker client with configuration
func initDockerClient(cfg *config.Config) (*client.Client, error) {
	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}

	// Override endpoint if specified
	if cfg.Docker.Endpoint != "" {
		opts = append(opts, client.WithHost(cfg.Docker.Endpoint))
	}

	// Set API version if specified
	if cfg.Docker.APIVersion != "" {
		opts = append(opts, client.WithVersion(cfg.Docker.APIVersion))
	}

	// TODO: Task 1.3 - Add TLS support
	// if cfg.Docker.TLSVerify {
	//     opts = append(opts, client.WithTLSClientConfig(...))
	// }

	dockerClient, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = dockerClient.Ping(ctx)
	if err != nil {
		dockerClient.Close()
		return nil, fmt.Errorf("docker ping failed: %w", err)
	}

	log.Println("✅ Docker client connected")
	return dockerClient, nil
}
