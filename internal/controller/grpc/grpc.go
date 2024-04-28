package grpc

import (
	"context"

	"github.com/NikolaB131/nmap-vulners-service/internal/entity"
	nmap_vulners_service "github.com/NikolaB131/nmap-vulners-service/pkg/proto"
	"google.golang.org/grpc"
)

type VulnersService interface {
	CheckVuln(ctx context.Context, targets []string, tcpPorts []int) ([]entity.Target, error)
}

type GRPCController struct {
	nmap_vulners_service.UnimplementedNetVulnServiceServer
	vulners VulnersService
}

func Register(gRPCServer *grpc.Server, vulners VulnersService) {
	nmap_vulners_service.RegisterNetVulnServiceServer(gRPCServer, &GRPCController{vulners: vulners})
}

func (c *GRPCController) CheckVuln(ctx context.Context, req *nmap_vulners_service.CheckVulnRequest) (*nmap_vulners_service.CheckVulnResponse, error) {
	return nil, nil
}
