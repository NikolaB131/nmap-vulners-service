package grpc

import (
	"context"
	"errors"
	"strconv"

	"github.com/NikolaB131/nmap-vulners-service/internal/entity"
	"github.com/NikolaB131/nmap-vulners-service/internal/service"
	nmap_vulners_service "github.com/NikolaB131/nmap-vulners-service/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type VulnersService interface {
	CheckVuln(ctx context.Context, targets []string, tcpPorts []string) ([]entity.HostResult, error)
}

type GRPCController struct {
	nmap_vulners_service.UnimplementedNetVulnServiceServer
	vulners VulnersService
}

func Register(gRPCServer *grpc.Server, vulners VulnersService) {
	nmap_vulners_service.RegisterNetVulnServiceServer(gRPCServer, &GRPCController{vulners: vulners})
}

func (c *GRPCController) CheckVuln(ctx context.Context, req *nmap_vulners_service.CheckVulnRequest) (*nmap_vulners_service.CheckVulnResponse, error) {
	ports := req.GetTcpPorts()
	targets := req.GetTargets()

	if len(targets) == 0 {
		return nil, status.Error(codes.InvalidArgument, "targets is required")
	}
	for _, target := range targets {
		if len(target) == 0 {
			return nil, status.Error(codes.InvalidArgument, "target cannot be an empty string")
		}
	}

	convertedPorts := make([]string, len(ports))
	for i := 0; i < len(ports); i++ {
		convertedPorts[i] = strconv.Itoa(int(ports[i]))
	}

	checkVulnResult, err := c.vulners.CheckVuln(ctx, req.GetTargets(), convertedPorts)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrScanTimeout):
			return nil, status.Error(codes.DeadlineExceeded, err.Error())
		default:
			return nil, status.Error(codes.Internal, "failed to check vulnerability")
		}
	}

	results := make([]*nmap_vulners_service.TargetsResult, len(checkVulnResult))

	for i, host := range checkVulnResult {
		target := &nmap_vulners_service.TargetsResult{
			Target:   host.TargetIP,
			Services: make([]*nmap_vulners_service.Service, len(host.Services)),
		}

		for j, service := range host.Services {
			tempService := &nmap_vulners_service.Service{
				Name:    service.Name,
				Version: service.Version,
				TcpPort: int32(service.TcpPort),
				Vulns:   make([]*nmap_vulners_service.Vulnerability, len(service.Vulns)),
			}

			for k, vuln := range service.Vulns {
				tempService.Vulns[k] = &nmap_vulners_service.Vulnerability{
					Identifier: vuln.Identifier,
					CvssScore:  vuln.CvssScore,
				}
			}
			target.Services[j] = tempService
		}
		results[i] = target
	}

	return &nmap_vulners_service.CheckVulnResponse{Results: results}, nil
}
