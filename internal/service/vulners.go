package service

import (
	"context"
	"log/slog"

	"github.com/NikolaB131/nmap-vulners-service/internal/entity"
)

type Vulners struct {
	log *slog.Logger
}

func NewVulnersService(logger *slog.Logger) *Vulners {
	return &Vulners{log: logger}
}

func (v *Vulners) CheckVuln(ctx context.Context, targets []string, tcpPorts []int) ([]entity.Target, error) {
	return nil, nil
}
