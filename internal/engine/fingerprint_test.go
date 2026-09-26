package engine

import "testing"

func fpVersion(fps []Fingerprint, product string) (string, bool) {
	for _, f := range fps {
		if f.Product == product {
			return f.Version, true
		}
	}
	return "", false
}

func TestExtractFingerprintsHeaders(t *testing.T) {
	resp := &Response{
		Headers: map[string]string{
			"Server":       "openresty/1.21.4",
			"X-Powered-By": "PHP/8.1.2",
		},
		Body: `<meta name="generator" content="WordPress 6.4.2"> <script src="/js/bootstrap-5.3.0.min.js"></script>`,
	}
	fps := ExtractFingerprints(resp)

	for product, want := range map[string]string{
		"openresty": "1.21.4",
		"php":       "8.1.2",
		"wordpress": "6.4.2",
		"bootstrap": "5.3.0",
	} {
		got, ok := fpVersion(fps, product)
		if !ok {
			t.Errorf("no se detectó %s", product)
			continue
		}
		if got != want {
			t.Errorf("%s: versión %q, want %q", product, got, want)
		}
	}
}

func TestExtractFingerprintFromBanner(t *testing.T) {
	cases := map[string]struct{ product, version string }{
		"SSH-2.0-OpenSSH_8.9p1":          {"openssh", "8.9"},
		"220 ProFTPD 1.3.5 Server ready": {"proftpd", "1.3.5"},
		"220 (vsFTPd 2.3.4)":             {"vsftpd", "2.3.4"},
	}
	for banner, want := range cases {
		fps := ExtractFingerprintFromBanner(banner)
		got, ok := fpVersion(fps, want.product)
		if !ok {
			t.Errorf("banner %q: no detectó %s", banner, want.product)
			continue
		}
		if got != want.version {
			t.Errorf("banner %q: %s versión %q, want %q", banner, want.product, got, want.version)
		}
	}
}

func TestNoFalsePositiveOnPlainServer(t *testing.T) {
	// Un Server sin versión no debe producir fingerprints.
	resp := &Response{Headers: map[string]string{"Server": "cloudflare"}, Body: ""}
	if fps := ExtractFingerprints(resp); len(fps) != 0 {
		t.Errorf("no se esperaban fingerprints, got %+v", fps)
	}
}
