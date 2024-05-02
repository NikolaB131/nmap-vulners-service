package entity

type (
	HostResult struct {
		TargetIP string
		Services []Service
	}

	Service struct {
		Name    string
		Version string
		TcpPort uint16
		Vulns   []Vulnerability
	}

	Vulnerability struct {
		Identifier string
		CvssScore  float32
	}
)
