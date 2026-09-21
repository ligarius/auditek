package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func findByRuleID(findings []Finding, ruleID string) *Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// TestScanSkipsBlanketRedirectToHome reproduce el caso real de un sitio que
// redirige CUALQUIER path a la home ("/") en vez de responder al recurso
// pedido (ej. biobio.cl redirigiendo /graphql a la home). Evaluar matchers
// sobre ese contenido no relacionado produce falsos positivos, así que el
// scanner debe omitir el hallazgo en vez de reportarlo.
func TestScanSkipsBlanketRedirectToHome(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("<html>homepage — contains the word types somewhere</html>"))
			return
		}
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	rules := []Rule{
		{
			ID:   "fake-graphql-introspection",
			Info: Info{Name: "fake", Severity: "medium"},
			Type: "http",
			HTTP: []HTTPRequest{
				{
					Method: "GET",
					Path:   []string{"{{BaseURL}}/graphql"},
					Matchers: []Matcher{
						{Type: "word", Part: "body", Words: []string{"types"}},
					},
				},
			},
		},
	}

	scanner := NewHTTPScanner(rules, 0, nil)
	findings := scanner.Scan(server.URL)

	if f := findByRuleID(findings, "fake-graphql-introspection"); f != nil {
		t.Errorf("no se esperaba hallazgo cuando el sitio redirige el path pedido a la home; got %+v", f)
	}
}

// TestScanReportsDirectPathMatch confirma que el guard de blanket-redirect
// no bloquea el caso normal: un recurso que responde directamente (sin
// redirect) al path exacto solicitado sí debe seguir generando hallazgos.
func TestScanReportsDirectPathMatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("homepage"))
	})
	mux.HandleFunc("/direct", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("contains types directly"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	rules := []Rule{
		{
			ID:   "fake-direct-match",
			Info: Info{Name: "fake", Severity: "low"},
			Type: "http",
			HTTP: []HTTPRequest{
				{
					Method: "GET",
					Path:   []string{"{{BaseURL}}/direct"},
					Matchers: []Matcher{
						{Type: "word", Part: "body", Words: []string{"types"}},
					},
				},
			},
		},
	}

	scanner := NewHTTPScanner(rules, 0, nil)
	findings := scanner.Scan(server.URL)

	if f := findByRuleID(findings, "fake-direct-match"); f == nil {
		t.Error("esperaba un hallazgo cuando el recurso responde directamente al path pedido")
	}
}

// TestScanHTTPNotRedirectingHTTPS reproduce el bug real de la regla
// "http-not-redirecting-https": sin force_scheme+no_follow_redirects, la
// regla siempre pasaba porque BaseURL ya viene en https y el cliente sigue
// redirects automáticamente. Con esas dos opciones, debe reportar solo
// cuando el servidor responde 200 directo sobre HTTP (sin redirigir).
func TestScanHTTPNotRedirectingHTTPS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	rules := []Rule{
		{
			ID:   "fake-http-not-redirecting-https",
			Info: Info{Name: "fake", Severity: "medium"},
			Type: "http",
			HTTP: []HTTPRequest{
				{
					Method:            "GET",
					Path:              []string{"{{BaseURL}}/"},
					ForceScheme:       "http",
					NoFollowRedirects: true,
					Matchers: []Matcher{
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
	}

	scanner := NewHTTPScanner(rules, 0, nil)
	findings := scanner.Scan(server.URL)

	if f := findByRuleID(findings, "fake-http-not-redirecting-https"); f == nil {
		t.Error("esperaba un hallazgo: el servidor responde 200 directo sobre HTTP sin redirigir")
	}
}

// TestScanHTTPRedirectingHTTPSNoFinding confirma el caso contrario: si el
// servidor SÍ redirige (3xx) en vez de responder 200 directo, no debe haber
// hallazgo — está redirigiendo correctamente.
func TestScanHTTPRedirectingHTTPSNoFinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	rules := []Rule{
		{
			ID:   "fake-http-not-redirecting-https",
			Info: Info{Name: "fake", Severity: "medium"},
			Type: "http",
			HTTP: []HTTPRequest{
				{
					Method:            "GET",
					Path:              []string{"{{BaseURL}}/"},
					ForceScheme:       "http",
					NoFollowRedirects: true,
					Matchers: []Matcher{
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
	}

	scanner := NewHTTPScanner(rules, 0, nil)
	findings := scanner.Scan(server.URL)

	if f := findByRuleID(findings, "fake-http-not-redirecting-https"); f != nil {
		t.Errorf("no se esperaba hallazgo: el servidor redirige correctamente, got %+v", f)
	}
}

func TestWithScheme(t *testing.T) {
	got := withScheme("https://example.com/path?q=1", "http")
	want := "http://example.com/path?q=1"
	if got != want {
		t.Errorf("withScheme() = %q, want %q", got, want)
	}
}

func TestPathOf(t *testing.T) {
	cases := map[string]string{
		"https://example.com/foo/bar": "/foo/bar",
		"https://example.com":         "/",
		"not a url \x7f":               "/",
	}
	for in, want := range cases {
		if got := pathOf(in); got != want {
			t.Errorf("pathOf(%q) = %q, want %q", in, got, want)
		}
	}
}
