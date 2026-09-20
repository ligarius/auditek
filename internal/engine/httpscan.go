package engine

import (
	"auditek/internal/cvedb"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPScanner struct {
	Rules   []Rule
	Client  *http.Client
	DelayMs int // pausa entre requests, en milisegundos (0 = sin límite)
	// Headers se agregan a CADA request del scan — pensado para autenticación
	// (ej. "Cookie: session=...", "Authorization: Bearer ...") en sitios que
	// no son públicos o que requieren estar logueado para ver ciertas rutas.
	Headers map[string]string
}

func NewHTTPScanner(rules []Rule, delayMs int, headers map[string]string) *HTTPScanner {
	return &HTTPScanner{
		Rules:   rules,
		DelayMs: delayMs,
		Headers: headers,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (s *HTTPScanner) Scan(baseURL string) []Finding {
	var findings []Finding

	fmt.Printf("\n🔍 Iniciando escaneo de: %s\n", baseURL)
	fmt.Printf("   Reglas a aplicar: %d\n", len(s.Rules))
	fmt.Println("   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Fase 1: Verificación de TLS y certificado
	fmt.Print("   [1/3] Verificando TLS y certificado...")
	if resp, err := s.doRequest("GET", baseURL); err == nil {
		// Solo procesar si NO es un redirect (3xx)
		if !isRedirect(resp.StatusCode) {
			if resp.TLSVersion == "TLSv1.0" || resp.TLSVersion == "TLSv1.1" {
				findings = append(findings, Finding{
					RuleID:    "weak-tls-version",
					RuleName:  fmt.Sprintf("Versión de TLS obsoleta detectada (%s)", resp.TLSVersion),
					Target:    baseURL,
					Severity:  "high",
					Impact:    "Permite ataques de downgrade y man-in-the-middle: un atacante en la misma red puede interceptar o alterar el tráfico explotando debilidades conocidas de TLS 1.0/1.1 (ej. BEAST, POODLE).",
					Timestamp: time.Now(),
					Evidence:  resp.TLSVersion,
				})
			}

			if resp.Cert != nil {
				findings = append(findings, certFindings(baseURL, resp.Cert)...)
			}

			if resp.StatusCode == 200 {
				if missing := FindExternalScriptsWithoutSRI(resp.Body, baseURL); len(missing) > 0 {
					findings = append(findings, Finding{
						RuleID:   "missing-sri-external-script",
						RuleName: "Scripts externos sin Subresource Integrity (SRI)",
						Target:   baseURL,
						Severity: "medium",
						Impact:   "Si el proveedor externo (CDN, librería de terceros) es comprometido, el script servido desde ahí se ejecutaría en el sitio sin ninguna verificación — es el vector de varios ataques de supply chain conocidos (ej. compromisos de CDN que afectaron miles de sitios simultáneamente).",
						Timestamp: time.Now(),
						Evidence:  strings.Join(missing, "\n"),
					})
				}

				for _, fp := range ExtractFingerprints(resp) {
					for _, cve := range cvedb.Lookup(fp.Product, fp.Version) {
						findings = append(findings, Finding{
							RuleID:    cve.CVE,
							RuleName:  fmt.Sprintf("%s (%s %s)", cve.Description, fp.Product, fp.Version),
							Target:    baseURL,
							Severity:  cve.Severity,
							CVE:       []string{cve.CVE},
							Impact:    cve.Impact,
							Timestamp: time.Now(),
							Evidence:  fmt.Sprintf("Versión detectada: %s %s", fp.Product, fp.Version),
						})
					}
				}
			}
		}

		// Buscar manifiestos de dependencias (solo si 200)
		for _, manifestPath := range []string{"/package.json", "/composer.json"} {
			if mresp, err := s.doRequest("GET", baseURL+manifestPath); err == nil && mresp.StatusCode == 200 {
				findings = append(findings, AnalyzeDependencyManifest(mresp.Body, baseURL+manifestPath, manifestPath)...)
			}
		}

		fmt.Printf(" ✓ (%d hallazgos)\n", len(findings))
	} else {
		fmt.Println(" ✗ (no se pudo conectar)")
	}

	// Fase 2: Escaneo de reglas HTTP
	fmt.Printf("   [2/3] Aplicando %d reglas de seguridad...\n", len(s.Rules))
	rulesProcessed := 0
	httpRuleCount := 0
	for _, rule := range s.Rules {
		if rule.Type != "http" {
			continue
		}
		httpRuleCount++
	}

	for _, rule := range s.Rules {
		if rule.Type != "http" {
			continue
		}

		rulesProcessed++
		// Mostrar progreso cada 5 reglas o al final
		if rulesProcessed%5 == 0 || rulesProcessed == httpRuleCount {
			fmt.Printf("        Procesadas %d/%d reglas...\r", rulesProcessed, httpRuleCount)
		}

		for _, req := range rule.HTTP {
			for _, path := range req.Path {
				url := strings.Replace(path, "{{BaseURL}}", baseURL, 1)

				if s.DelayMs > 0 {
					time.Sleep(time.Duration(s.DelayMs) * time.Millisecond)
				}

				resp, err := s.doRequest(req.Method, url)
				if err != nil {
					continue
				}

				// IMPORTANTE: No reportar si es un redirect (3xx)
				// Los redirects son normales, no son vulnerabilidades
				if isRedirect(resp.StatusCode) {
					continue
				}

				// Evaluar matchers SOLO si el status code es apropiado
				if EvaluateMatchers(req.Matchers, req.MatchersCondition, resp) {
					findings = append(findings, Finding{
						RuleID:    rule.ID,
						RuleName:  rule.Info.Name,
						Target:    url,
						Severity:  rule.Info.Severity,
						CVE:       rule.Info.CVE,
						Impact:    rule.Info.Impact,
						Timestamp: time.Now(),
						Evidence:  truncate(resp.Body, 200),
					})
				}
			}
		}
	}
	fmt.Printf("        Procesadas %d/%d reglas... ✓\n", httpRuleCount, httpRuleCount)

	// Fase 3: Resumen
	fmt.Println("   [3/3] Finalizando...")
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		case "info":
			infoCount++
		}
	}

	fmt.Println("   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("   📊 Resumen de hallazgos:\n")
	if criticalCount > 0 {
		fmt.Printf("      🔴 Crítico: %d\n", criticalCount)
	}
	if highCount > 0 {
		fmt.Printf("      🟠 Alto: %d\n", highCount)
	}
	if mediumCount > 0 {
		fmt.Printf("      🟡 Medio: %d\n", mediumCount)
	}
	if lowCount > 0 {
		fmt.Printf("      🟢 Bajo: %d\n", lowCount)
	}
	if infoCount > 0 {
		fmt.Printf("      ℹ️  Información: %d\n", infoCount)
	}
	fmt.Printf("   Total: %d hallazgo(s)\n", len(findings))
	fmt.Println()

	return findings
}

// isRedirect verifica si el status code es un redirect (3xx)
// Los redirects son respuestas normales, no vulnerabilidades
func isRedirect(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

// certFindings evalúa el certificado TLS presentado y genera hallazgos de
// configuración (no de vulnerabilidad de software): auto-firmado, vencido,
// o por vencer en menos de 30 días. Un cert auto-firmado en producción no
// es "inseguro" criptográficamente, pero rompe la cadena de confianza que
// los navegadores esperan — los visitantes ven advertencias, y es señal de
// que TLS se configuró apurado o mal.
func certFindings(target string, cert *CertInfo) []Finding {
	var out []Finding
	now := time.Now()

	if cert.SelfSigned {
		out = append(out, Finding{
			RuleID:    "tls-cert-self-signed",
			RuleName:  "Certificado TLS auto-firmado",
			Target:    target,
			Severity:  "medium",
			Impact:    "Los navegadores muestran advertencias de seguridad a los visitantes, dañando confianza; además, un cert auto-firmado no protege contra man-in-the-middle de la misma forma que uno emitido por una CA confiable, porque cualquiera puede generar uno igual de válido a simple vista.",
			Timestamp: now,
			Evidence:  fmt.Sprintf("Subject y Issuer coinciden: %s", cert.Subject),
		})
	}

	if cert.NotAfter.Before(now) {
		out = append(out, Finding{
			RuleID:    "tls-cert-expired",
			RuleName:  "Certificado TLS vencido",
			Target:    target,
			Severity:  "high",
			Impact:    "El certificado ya venció — los navegadores bloquean o advierten fuertemente a los visitantes, y técnicamente ya no hay garantía de identidad del servidor.",
			Timestamp: now,
			Evidence:  fmt.Sprintf("Venció el %s", cert.NotAfter.Format("2006-01-02")),
		})
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		out = append(out, Finding{
			RuleID:    "tls-cert-expiring-soon",
			RuleName:  "Certificado TLS vence pronto",
			Target:    target,
			Severity:  "low",
			Impact:    "Si no se renueva a tiempo, el sitio quedará con un certificado vencido — riesgo operacional más que de seguridad, pero fácil de prevenir.",
			Timestamp: now,
			Evidence:  fmt.Sprintf("Vence el %s", cert.NotAfter.Format("2006-01-02")),
		})
	}

	return out
}

func (s *HTTPScanner) doRequest(method, url string) (*Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	tlsVersion := ""
	var certInfo *CertInfo
	if resp.TLS != nil {
		tlsVersion = tlsVersionName(resp.TLS.Version)
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			certInfo = &CertInfo{
				Subject:    cert.Subject.CommonName,
				Issuer:     cert.Issuer.CommonName,
				NotAfter:   cert.NotAfter,
				SelfSigned: cert.Subject.CommonName != "" && cert.Subject.CommonName == cert.Issuer.CommonName,
			}
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       string(body),
		Headers:    headers,
		TLSVersion: tlsVersion,
		Cert:       certInfo,
	}, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return "unknown"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
