package tests

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	grpccontroller "github.com/NikolaB131/nmap-vulners-service/internal/controller/grpc"
	"github.com/NikolaB131/nmap-vulners-service/internal/service"
	nmap_vulners_service "github.com/NikolaB131/nmap-vulners-service/pkg/proto"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const containsVulnMsg = "Result does not conatain vulnerability"

var (
	scanResultLocalhostPort11001 = []*nmap_vulners_service.Vulnerability{
		{
			Identifier: "CVE-2018-10933",
			CvssScore:  6.4,
		},
		{
			Identifier: "CVE-2019-14889",
			CvssScore:  9.3,
		},
		{
			Identifier: "CVE-2020-1730",
			CvssScore:  5,
		},
	}
)

type VulnersControllerSuite struct {
	suite.Suite

	serverListener *bufconn.Listener
	server         *grpc.Server
	clientConn     *grpc.ClientConn
	Client         nmap_vulners_service.NetVulnServiceClient
}

func TestVulnersControllerSuite(t *testing.T) {
	suite.Run(t, new(VulnersControllerSuite))
}

func (s *VulnersControllerSuite) SetupSuite() {
	s.serverListener = bufconn.Listen(1024 * 1024)
	s.server = grpc.NewServer()

	vulnersService := service.NewVulnersService(slog.Default(), 2*time.Minute, "../../scripts/vulners.nse")
	grpccontroller.Register(s.server, vulnersService)

	go func() {
		err := s.server.Serve(s.serverListener)
		s.NoError(err)
	}()

	conn, err := grpc.Dial(
		"bufnet",
		grpc.WithContextDialer(func(ctx context.Context, str string) (net.Conn, error) {
			return s.serverListener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	s.Require().NoError(err)
	s.clientConn = conn

	s.Client = nmap_vulners_service.NewNetVulnServiceClient(s.clientConn)
}

func (s *VulnersControllerSuite) TearDownSuite() {
	if s.serverListener != nil {
		s.server.GracefulStop()
		s.serverListener.Close()

	}
	if s.clientConn != nil {
		s.clientConn.Close()
	}
}

func (s *VulnersControllerSuite) TestCheckVuln_1() { // One target, one port
	ctx := context.Background()
	response, err := s.Client.CheckVuln(ctx, &nmap_vulners_service.CheckVulnRequest{
		Targets:  []string{"localhost"},
		TcpPorts: []int32{11001},
	})
	s.Require().NoError(err)

	res := response.GetResults()[0]
	service := res.Services[0]
	s.Equal("127.0.0.1", res.Target)
	s.Equal("ssh", service.Name)
	s.Equal("0.8.1", service.Version)
	s.Equal(service.TcpPort, int32(11001))
	for _, vuln := range scanResultLocalhostPort11001 {
		s.Contains(service.Vulns, vuln, containsVulnMsg)
	}
}

func (s *VulnersControllerSuite) TestCheckVuln_2() { // Multiple targets, one port
	ctx := context.Background()
	response, err := s.Client.CheckVuln(ctx, &nmap_vulners_service.CheckVulnRequest{
		Targets:  []string{"localhost", "nikolab131.xyz"},
		TcpPorts: []int32{11001},
	})
	s.Require().NoError(err)

	localhostRes := response.GetResults()[0]
	service := localhostRes.Services[0]
	s.Equal("127.0.0.1", localhostRes.Target)
	s.Equal("ssh", service.Name)
	s.Equal("0.8.1", service.Version)
	s.Equal(int32(11001), service.TcpPort)
	for _, vuln := range scanResultLocalhostPort11001 {
		s.Contains(service.Vulns, vuln, containsVulnMsg)
	}

	nikolab131Res := response.GetResults()[1]
	s.Equal("178.140.10.168", nikolab131Res.Target)
	s.Empty(nikolab131Res.Services)
}

func (s *VulnersControllerSuite) TestCheckVuln_3() { // One target, multiple ports
	ctx := context.Background()
	response, err := s.Client.CheckVuln(ctx, &nmap_vulners_service.CheckVulnRequest{
		Targets:  []string{"localhost"},
		TcpPorts: []int32{11001, 11002},
	})
	s.Require().NoError(err)

	res := response.GetResults()[0]
	s.Equal("127.0.0.1", res.Target)

	firstService := res.Services[0]
	s.Equal("ssh", firstService.Name)
	s.Equal(int32(11001), firstService.TcpPort)
	for _, vuln := range scanResultLocalhostPort11001 {
		s.Contains(firstService.Vulns, vuln, containsVulnMsg)
	}

	secondService := res.Services[1]
	s.Equal("http", secondService.Name)
	s.Equal("1.13.2", secondService.Version)
	s.Equal(int32(11002), secondService.TcpPort)
	s.Contains(secondService.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "NGINX:CVE-2017-7529", CvssScore: 5}, containsVulnMsg)
	s.Contains(secondService.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "SSV:96273", CvssScore: 5}, containsVulnMsg)
	s.Contains(secondService.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "PRION:CVE-2017-20005", CvssScore: 7.5}, containsVulnMsg)
}

func (s *VulnersControllerSuite) TestCheckVuln_4() { // Multiple targets, multiple ports
	ctx := context.Background()
	response, err := s.Client.CheckVuln(ctx, &nmap_vulners_service.CheckVulnRequest{
		Targets:  []string{"localhost", "nikolab131.xyz"},
		TcpPorts: []int32{11001, 11002, 22, 80, 443},
	})
	s.Require().NoError(err)

	localhostRes := response.GetResults()[0]
	firstService := localhostRes.Services[0]
	s.Equal("127.0.0.1", localhostRes.Target)
	s.Equal("ssh", firstService.Name)
	s.Equal("0.8.1", firstService.Version)
	s.Equal(int32(11001), firstService.TcpPort)
	for _, vuln := range scanResultLocalhostPort11001 {
		s.Contains(firstService.Vulns, vuln, containsVulnMsg)
	}
	secondService := localhostRes.Services[1]
	s.Equal("http", secondService.Name)
	s.Equal("1.13.2", secondService.Version)
	s.Equal(int32(11002), secondService.TcpPort)
	s.Contains(secondService.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "NGINX:CVE-2017-7529", CvssScore: 5}, containsVulnMsg)
	s.Contains(secondService.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "SSV:96273", CvssScore: 5}, containsVulnMsg)
	s.Contains(secondService.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "PRION:CVE-2017-20005", CvssScore: 7.5}, containsVulnMsg)

	nikolab131Res := response.GetResults()[1]
	service := nikolab131Res.Services[0]
	s.Equal(1, len(nikolab131Res.Services))
	s.Equal("ssh", service.Name)
	s.Equal("8.2p1 Ubuntu 4ubuntu0.11", service.Version)
	s.Equal(int32(22), service.TcpPort)
	s.Contains(service.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "CVE-2016-20012", CvssScore: 4.3}, containsVulnMsg)
	s.Contains(service.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "CVE-2021-28041", CvssScore: 4.6}, containsVulnMsg)
	s.Contains(service.Vulns, &nmap_vulners_service.Vulnerability{Identifier: "CVE-2012-1577", CvssScore: 7.5}, containsVulnMsg)
}

func (s *VulnersControllerSuite) TestCheckVuln_Empty() {
	ctx := context.Background()
	response, err := s.Client.CheckVuln(ctx, &nmap_vulners_service.CheckVulnRequest{
		Targets:  []string{"ya.ru"},
		TcpPorts: []int32{22},
	})
	s.Require().NoError(err)

	s.NotEmpty(response.GetResults()[0].Target)
	s.Empty(response.GetResults()[0].Services)
}

func (s *VulnersControllerSuite) TestCheckVuln_Validation() {
	ctx := context.Background()
	_, err := s.Client.CheckVuln(ctx, &nmap_vulners_service.CheckVulnRequest{
		Targets:  []string{""},
		TcpPorts: []int32{22},
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			s.Equal(codes.InvalidArgument, e.Code())
			s.Equal("target cannot be an empty string", e.Message())
		} else {
			panic(fmt.Errorf("not able to parse error: %w", err))
		}
	}

	_, err = s.Client.CheckVuln(ctx, &nmap_vulners_service.CheckVulnRequest{TcpPorts: []int32{22}})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			s.Equal(codes.InvalidArgument, e.Code())
			s.Equal("targets is required", e.Message())
		} else {
			panic(fmt.Errorf("not able to parse error: %w", err))
		}
	}
}
