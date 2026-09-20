package engine

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type TCPScanner struct {
	Rules []Rule
}

func NewTCPScanner(rules []Rule) *TCPScanner {
	return &TCPScanner{Rules: rules}
}

// Scan conecta a cada puerto definido en reglas type:tcp contra el host dado,
// envía los datos de sondeo (si hay) y evalúa la respuesta con los matchers.
// allowedPorts limita qué puertos se prueban — si un rule.TCP[].Port no está
// en allowedPorts, se omite. Esto es lo que hace que --ports también limite
// el scope de las reglas de protocolo, no solo el descubrimiento de puertos
// genérico; un nil o mapa vacío significa "sin restricción" (permite todos).
func (s *TCPScanner) Scan(host string, allowedPorts map[int]bool) []Finding {
	var findings []Finding

	for _, rule := range s.Rules {
		if rule.Type != "tcp" {
			continue
		}

		for _, req := range rule.TCP {
			if len(allowedPorts) > 0 && !allowedPorts[req.Port] {
				continue
			}

			resp, err := probeTCP(host, req)
			if err != nil {
				continue // puerto cerrado o no responde — no es un hallazgo
			}

			if EvaluateMatchers(req.Matchers, req.Condition, resp) {
				findings = append(findings, Finding{
					RuleID:    rule.ID,
					RuleName:  rule.Info.Name,
					Target:    fmt.Sprintf("%s:%d", host, req.Port),
					Severity:  rule.Info.Severity,
					CVE:       rule.Info.CVE,
					Impact:    rule.Info.Impact,
					Timestamp: time.Now(),
					Evidence:  truncate(resp.Body, 200),
				})
			}
		}
	}

	return findings
}

func probeTCP(host string, req TCPRequest) (*Response, error) {
	timeout := 3 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	address := fmt.Sprintf("%s:%d", host, req.Port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	steps := req.Steps
	if len(steps) == 0 {
		// atajo legacy: un solo paso con `data` (o ninguno, solo leer el banner)
		steps = []TCPStep{{Send: req.Data}}
	}

	var combined strings.Builder
	for _, step := range steps {
		if step.Send != "" {
			conn.SetWriteDeadline(time.Now().Add(timeout))
			if _, err := conn.Write([]byte(step.Send)); err != nil {
				return nil, err
			}
		}

		conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			// Si ya leímos algo en pasos previos, devolvemos lo acumulado en vez
			// de fallar — un timeout en el último paso no invalida lo anterior.
			if combined.Len() > 0 {
				break
			}
			return nil, err
		}
		combined.Write(buf[:n])
	}

	return &Response{Body: combined.String()}, nil
}
