package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type (
	Config struct {
		GRPC    `yaml:"grpc"`
		Logger  `yaml:"logger"`
		Vulners `yaml:"vulners"`
	}

	GRPC struct {
		Port int `yaml:"port"`
	}

	Logger struct {
		Level string `yaml:"level"`
	}

	Vulners struct {
		CheckTimeout time.Duration `yaml:"check_timeout"`
	}
)

func NewConfig(path string) (*Config, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config reading yaml file error: %w", err)
	}

	// Default values
	config := Config{
		GRPC: GRPC{
			Port: 3000,
		},
		Logger: Logger{
			Level: "info",
		},
		Vulners: Vulners{
			CheckTimeout: time.Minute,
		},
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, fmt.Errorf("config parsing yaml file error: %w", err)
	}

	// Parse environment variables
	gRPCPort, ok := os.LookupEnv("GRPC_PORT")
	if ok {
		grpcPortInt, err := strconv.Atoi(gRPCPort)
		if err != nil {
			return nil, fmt.Errorf("environment variable GRPC_PORT converting error: %w", err)
		}
		config.GRPC.Port = grpcPortInt
	}

	loggerLevel, ok := os.LookupEnv("LOGGER_LEVEL")
	if ok {
		config.Logger.Level = loggerLevel
	}

	vulnersCheckTimeout, ok := os.LookupEnv("VULNERS_CHECK_TIMEOUT")
	if ok {
		timeoutParsed, err := time.ParseDuration(vulnersCheckTimeout)
		if err != nil {
			return nil, fmt.Errorf("environment variable VULNERS_CHECK_TIMEOUT parsing error: %w", err)
		}
		config.Vulners.CheckTimeout = timeoutParsed
	}

	return &config, nil
}
