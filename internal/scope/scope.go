package scope

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	yaml "github.com/goccy/go-yaml"
)

type Target struct {
	Domain     string `yaml:"domain,omitempty"`
	Subdomains bool   `yaml:"subdomains,omitempty"`
	IPRange    string `yaml:"ip_range,omitempty"`
}

type Scope struct {
	AuthorizedBy string   `yaml:"authorized_by"`
	DateSigned   string   `yaml:"date_signed"`
	Targets      []Target `yaml:"targets"`
	Excluded     []string `yaml:"excluded"`
}

func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer scope file: %w", err)
	}

	var s Scope
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("scope.yaml inválido: %w", err)
	}

	if err := s.validate(); err != nil {
		return nil, err
	}

	return &s, nil
}

func (s *Scope) validate() error {
	if s.AuthorizedBy == "" {
		return fmt.Errorf("scope.yaml debe indicar 'authorized_by'")
	}
	if len(s.Targets) == 0 {
		return fmt.Errorf("scope.yaml debe declarar al menos un target")
	}
	if _, err := time.Parse("2006-01-02", s.DateSigned); err != nil {
		return fmt.Errorf("date_signed inválido, formato esperado YYYY-MM-DD")
	}
	return nil
}

func (s *Scope) IsAuthorized(target string) bool {
	if s.IsExcluded(target) {
		return false
	}

	for _, t := range s.Targets {
		if t.Domain != "" && matchesDomain(target, t.Domain, t.Subdomains) {
			return true
		}
		if t.IPRange != "" && matchesIPRange(target, t.IPRange) {
			return true
		}
	}
	return false
}

func (s *Scope) IsExcluded(target string) bool {
	for _, ex := range s.Excluded {
		if strings.EqualFold(target, ex) || strings.HasSuffix(target, "."+ex) {
			return true
		}
	}
	return false
}

func matchesDomain(target, domain string, allowSubdomains bool) bool {
	target = strings.ToLower(target)
	domain = strings.ToLower(domain)
	if target == domain {
		return true
	}
	if allowSubdomains && strings.HasSuffix(target, "."+domain) {
		return true
	}
	return false
}

func matchesIPRange(target, cidr string) bool {
	ip := net.ParseIP(target)
	if ip == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}
