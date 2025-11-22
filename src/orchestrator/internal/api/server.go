package api

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/apto-as/tmws/orchestrator/api"
	"github.com/apto-as/tmws/orchestrator/internal/orchestrator"
)

var (
	// ErrToolNotFound is returned when a tool cannot be found
	ErrToolNotFound = status.Error(codes.NotFound, "tool not found")
	// ErrInvalidRequest is returned for invalid request parameters
	ErrInvalidRequest = status.Error(codes.InvalidArgument, "invalid request")
	// ErrInternal is returned for internal server errors
	ErrInternal = status.Error(codes.Internal, "internal server error")
)

// Server implements the gRPC OrchestratorService
type Server struct {
	pb.UnimplementedOrchestratorServiceServer
	orchestrator *orchestrator.Service
}

// NewServer creates a new gRPC server instance
func NewServer(svc *orchestrator.Service) *Server {
	return &Server{orchestrator: svc}
}

// DiscoverTools performs tool discovery across configured paths
func (s *Server) DiscoverTools(ctx context.Context, req *pb.DiscoverToolsRequest) (*pb.DiscoverToolsResponse, error) {
	log.Printf("DiscoverTools called with %d paths", len(req.Paths))

	// Use service's discovery engine
	tools, err := s.orchestrator.Discovery.ScanWithValidation()
	if err != nil {
		log.Printf("Discovery error: %v", err)
		return nil, status.Errorf(codes.Internal, "discovery failed: %v", err)
	}

	// Convert to protobuf format
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

	log.Printf("Discovered %d tools", len(protoTools))
	return &pb.DiscoverToolsResponse{
		Tools:      protoTools,
		TotalCount: int32(len(tools)),
	}, nil
}

// GetTool retrieves a specific tool by ID
func (s *Server) GetTool(ctx context.Context, req *pb.GetToolRequest) (*pb.Tool, error) {
	if req.ToolId == "" {
		return nil, status.Error(codes.InvalidArgument, "tool_id is required")
	}

	log.Printf("GetTool called for tool_id: %s", req.ToolId)

	// Scan for tools (uses cache if available)
	tools, err := s.orchestrator.Discovery.Scan()
	if err != nil {
		log.Printf("Scan error: %v", err)
		return nil, status.Errorf(codes.Internal, "scan failed: %v", err)
	}

	// Find matching tool
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

	log.Printf("Tool not found: %s", req.ToolId)
	return nil, ErrToolNotFound
}

// ListTools lists tools with optional category filter
func (s *Server) ListTools(ctx context.Context, req *pb.ListToolsRequest) (*pb.ListToolsResponse, error) {
	if req.Namespace == "" {
		return nil, status.Error(codes.InvalidArgument, "namespace is required")
	}

	log.Printf("ListTools called for namespace: %s, category: %s", req.Namespace, req.Category)

	// Scan for tools
	tools, err := s.orchestrator.Discovery.ScanWithValidation()
	if err != nil {
		log.Printf("Scan error: %v", err)
		return nil, status.Errorf(codes.Internal, "scan failed: %v", err)
	}

	// Filter by category if specified
	var filteredTools []*orchestrator.Tool
	if req.Category != "" {
		for _, tool := range tools {
			if tool.Category == req.Category {
				filteredTools = append(filteredTools, tool)
			}
		}
	} else {
		filteredTools = tools
	}

	// Convert to protobuf format
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

	log.Printf("Listed %d tools", len(protoTools))
	return &pb.ListToolsResponse{
		Tools: protoTools,
	}, nil
}

// StartContainer starts a Docker container for the specified tool
func (s *Server) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*pb.ContainerInstance, error) {
	if req.ToolId == "" {
		return nil, status.Error(codes.InvalidArgument, "tool_id is required")
	}

	log.Printf("StartContainer called for tool_id: %s", req.ToolId)

	// TODO: Implement container lifecycle management
	// For now, return a placeholder response
	return &pb.ContainerInstance{
		ContainerId: fmt.Sprintf("container-%s", req.ToolId),
		ToolId:      req.ToolId,
		Status:      "starting",
		StartedAt:   0, // TODO: timestamp
	}, status.Error(codes.Unimplemented, "container management not yet implemented")
}

// StopContainer stops a running container
func (s *Server) StopContainer(ctx context.Context, req *pb.StopContainerRequest) (*pb.StopContainerResponse, error) {
	if req.ContainerId == "" {
		return nil, status.Error(codes.InvalidArgument, "container_id is required")
	}

	log.Printf("StopContainer called for container_id: %s", req.ContainerId)

	// TODO: Implement container lifecycle management
	return &pb.StopContainerResponse{
		Success: false,
		Message: "container management not yet implemented",
	}, status.Error(codes.Unimplemented, "container management not yet implemented")
}

// GetContainerStatus retrieves the status of a running container
func (s *Server) GetContainerStatus(ctx context.Context, req *pb.GetContainerStatusRequest) (*pb.ContainerStatus, error) {
	if req.ContainerId == "" {
		return nil, status.Error(codes.InvalidArgument, "container_id is required")
	}

	log.Printf("GetContainerStatus called for container_id: %s", req.ContainerId)

	// TODO: Implement container lifecycle management
	return &pb.ContainerStatus{
		ContainerId:   req.ContainerId,
		Status:        "unknown",
		UptimeSeconds: 0,
		Stats:         nil,
	}, status.Error(codes.Unimplemented, "container management not yet implemented")
}
