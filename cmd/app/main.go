package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/NikolaB131/nmap-vulners-service/config"
	grpccontroller "github.com/NikolaB131/nmap-vulners-service/internal/controller/grpc"
	"github.com/NikolaB131/nmap-vulners-service/internal/service"
	"google.golang.org/grpc"
)

func main() {
	// Parse flags
	var configPath string
	flag.StringVar(&configPath, "c", "", "Path to yaml config file")
	flag.StringVar(&configPath, "config", "", "Path to yaml config file (long version)")
	flag.Parse()
	if configPath == "" {
		panic("Config file path is not specified")
	}

	// Config
	config, err := config.NewConfig(configPath)
	if err != nil {
		panic(err)
	}

	// Logger
	logger := initLogger(config.Logger.Level)
	logger.Info(
		"Logger initialized",
		slog.String("log_level", config.Logger.Level),
	)

	// Services
	vulnersService := service.NewVulnersService(logger)

	// Server
	gRPCServer := grpc.NewServer()

	grpccontroller.Register(gRPCServer, vulnersService)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.GRPC.Port))
	if err != nil {
		panic(err)
	}

	logger.Info(
		"gRPC server started",
		slog.Int("port", config.GRPC.Port),
	)

	err = gRPCServer.Serve(listener)
	if err != nil {
		panic(err)
	}
}

func initLogger(logLevel string) *slog.Logger {
	level := slog.LevelDebug

	switch logLevel {
	case "error":
		level = slog.LevelError
	case "warn":
		level = slog.LevelWarn
	case "info":
		level = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level, AddSource: true}))
}
