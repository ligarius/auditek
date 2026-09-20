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
	{"apache", regexp.MustCompile(`Apache/(\d+\.\d+\.\d+)`), "header:Server"},
	{"nginx", regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`), "header:Server"},
	{"iis", regexp.MustCompile(`Microsoft-IIS/(\d+\.\d+)`), "header:Server"},
	{"openssh", regexp.MustCompile(`OpenSSH[_/](\d+\.\d+)`), "banner"},
	{"vsftpd", regexp.MustCompile(`(?i)vsftpd (\d+\.\d+\.\d+)`), "banner"},
	{"exim", regexp.MustCompile(`Exim (\d+\.\d+)`), "banner"},
	{"php", regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`), "header:X-Powered-By"},
	{"jquery", regexp.MustCompile(`jquery[/-](\d+\.\d+\.\d+)`), "body"},
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
