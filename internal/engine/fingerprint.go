package engine

import "regexp"

// Fingerprint representa un producto+versión detectado en una respuesta HTTP.
type Fingerprint struct {
	Product string
	Version string
}

var fingerprintPatterns = []struct {
	product string
	re      *regexp.Regexp
	source  string // "header:Server", "header:X-Powered-By", "body", "banner"
}{
	// Servidores web / app (header Server, a veces en body/páginas de error)
	{"apache", regexp.MustCompile(`Apache/(\d+\.\d+\.\d+)`), "header:Server"},
	{"nginx", regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`), "header:Server"},
	{"iis", regexp.MustCompile(`Microsoft-IIS/(\d+\.\d+)`), "header:Server"},
	{"openresty", regexp.MustCompile(`openresty/(\d+\.\d+\.\d+)`), "header:Server"},
	{"lighttpd", regexp.MustCompile(`lighttpd/(\d+\.\d+\.\d+)`), "header:Server"},
	{"litespeed", regexp.MustCompile(`LiteSpeed/(\d+\.\d+(?:\.\d+)?)`), "header:Server"},
	{"tomcat", regexp.MustCompile(`(?:Apache Tomcat|Tomcat)/(\d+\.\d+\.\d+)`), "body"},
	{"jetty", regexp.MustCompile(`Jetty\((\d+\.\d+\.\d+)`), "header:Server"},
	{"gunicorn", regexp.MustCompile(`gunicorn/(\d+\.\d+\.\d+)`), "header:Server"},
	{"werkzeug", regexp.MustCompile(`Werkzeug/(\d+\.\d+\.\d+)`), "header:Server"},

	// Lenguajes / runtimes
	{"php", regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`), "header:X-Powered-By"},

	// CMS / frameworks / librerías (body: meta generator o el <script>)
	{"wordpress", regexp.MustCompile(`(?i)content="WordPress (\d+\.\d+(?:\.\d+)?)"`), "body"},
	{"drupal", regexp.MustCompile(`(?i)content="Drupal (\d+)`), "body"},
	{"jquery", regexp.MustCompile(`jquery[/-](\d+\.\d+\.\d+)`), "body"},
	{"bootstrap", regexp.MustCompile(`bootstrap[/-](\d+\.\d+\.\d+)`), "body"},

	// Servicios por banner TCP
	{"openssh", regexp.MustCompile(`OpenSSH[_/](\d+\.\d+)`), "banner"},
	{"vsftpd", regexp.MustCompile(`(?i)vsftpd (\d+\.\d+\.\d+)`), "banner"},
	{"proftpd", regexp.MustCompile(`(?i)ProFTPD (\d+\.\d+\.\d+)`), "banner"},
	{"exim", regexp.MustCompile(`Exim (\d+\.\d+)`), "banner"},
}

// ExtractFingerprints busca patrones de producto+versión conocidos en headers y body.
func ExtractFingerprints(resp *Response) []Fingerprint {
	var found []Fingerprint

	haystacks := []string{resp.Body}
	for _, v := range resp.Headers {
		haystacks = append(haystacks, v)
	}

	for _, p := range fingerprintPatterns {
		for _, h := range haystacks {
			if m := p.re.FindStringSubmatch(h); len(m) == 2 {
				found = append(found, Fingerprint{Product: p.product, Version: m[1]})
				break
			}
		}
	}
	return found
}

// ExtractFingerprintFromBanner aplica los mismos patrones sobre un banner TCP crudo
// (ej. "SSH-2.0-OpenSSH_7.4"), útil para hallazgos de escaneo de red.
func ExtractFingerprintFromBanner(banner string) []Fingerprint {
	var found []Fingerprint
	for _, p := range fingerprintPatterns {
		if m := p.re.FindStringSubmatch(banner); len(m) == 2 {
			found = append(found, Fingerprint{Product: p.product, Version: m[1]})
		}
	}
	return found
}
