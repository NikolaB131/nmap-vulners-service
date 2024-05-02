package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/NikolaB131/nmap-vulners-service/internal/entity"
	"github.com/NikolaB131/nmap-vulners-service/pkg/sl"
	"github.com/Ullaakut/nmap/v3"
)

var (
	ErrScanTimeout = errors.New("scan timeout")
)

type Vulners struct {
	log             *slog.Logger
	checkTimeout    time.Duration
	checkScriptPath string
}

func NewVulnersService(logger *slog.Logger, checkTimeout time.Duration, checkScriptPath string) *Vulners {
	return &Vulners{log: logger, checkTimeout: checkTimeout, checkScriptPath: checkScriptPath}
}

// TODO: make it faster using async for hosts
func (v *Vulners) CheckVuln(parentCtx context.Context, targets []string, tcpPorts []string) ([]entity.HostResult, error) {
	ctx, cancel := context.WithTimeout(parentCtx, v.checkTimeout)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(targets...),
		nmap.WithScripts(v.checkScriptPath),
		nmap.WithServiceInfo(),
	)
	if err != nil {
		v.log.Error("unable to create nmap scanner", sl.Err(err))
		return nil, err
	}
	if len(tcpPorts) > 0 {
		scanner.AddOptions(nmap.WithPorts(tcpPorts...))
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		for _, warning := range *warnings {
			v.log.Warn("nmap run finished with warning", slog.String("warning", warning))
		}
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrScanTimeout
		}
		v.log.Error("unable to run nmap scan", sl.Err(err))
		return nil, err
	}

	hostsResults := make([]entity.HostResult, len(result.Hosts))

	for i, host := range result.Hosts {
		hostResult := entity.HostResult{TargetIP: host.Addresses[0].Addr}

		for _, port := range host.Ports {
			var vulnersScript *nmap.Script
			for _, script := range port.Scripts {
				if script.ID == "vulners" {
					vulnersScript = &script
				}
			}
			if vulnersScript == nil { // checks vulners script result exists
				continue
			}
			service := entity.Service{
				Name:    port.Service.Name,
				Version: port.Service.Version,
				TcpPort: port.ID,
				Vulns:   make([]entity.Vulnerability, len(vulnersScript.Tables[0].Tables)),
			}

			for k, vuln := range vulnersScript.Tables[0].Tables {
				var vulnerability entity.Vulnerability

				for _, element := range vuln.Elements {
					switch element.Key {
					case "id":
						vulnerability.Identifier = element.Value
					case "cvss":
						cvss, err := strconv.ParseFloat(element.Value, 32)
						if err != nil {
							v.log.Error("unable to parse float from cvss version", sl.Err(err))
							return nil, err
						}
						vulnerability.CvssScore = float32(cvss)
					}
				}
				service.Vulns[k] = vulnerability
			}
			hostResult.Services = append(hostResult.Services, service)
		}
		hostsResults[i] = hostResult
	}

	v.log.Info(
		"nmap vulners scan done",
		slog.String("targets", strings.Join(targets, ", ")),
		slog.String("tcp_ports", strings.Join(tcpPorts, ", ")),
		slog.String("elapsed_time", fmt.Sprintf("%.2f seconds", result.Stats.Finished.Elapsed)),
	)
	return hostsResults, nil
}
