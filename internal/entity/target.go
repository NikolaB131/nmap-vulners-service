package entity

type Target struct { // TODO: maybe imagine better name
	TargetIP string
	Services []struct {
		Name    string
		Version string
		TcpPort int
		Vulns   []struct {
			Identifier string
			CvssScore  float32
		}
	}
}
