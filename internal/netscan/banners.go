package netscan

import "strings"

var wellKnownPorts = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 143: "imap", 443: "https",
	445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
	5900: "vnc", 6379: "redis", 8000: "http", 8080: "http-proxy", 27017: "mongodb",
}

func IdentifyService(port int, banner string) string {
	b := strings.ToLower(banner)

	switch {
	case strings.Contains(b, "ssh"):
		return "ssh"
	case strings.Contains(b, "http") || strings.Contains(b, "server:"):
		return "http"
	case strings.Contains(b, "mysql"):
		return "mysql"
	case strings.Contains(b, "smtp"):
		return "smtp"
	case strings.Contains(b, "ftp"):
		return "ftp"
	}

	if svc, ok := wellKnownPorts[port]; ok {
		return svc
	}
	return "unknown"
}
