package engine

import "time"

type Rule struct {
	ID   string        `yaml:"id"`
	Info Info          `yaml:"info"`
	Type string        `yaml:"type"`
	HTTP []HTTPRequest `yaml:"http,omitempty"`
	TCP  []TCPRequest  `yaml:"tcp,omitempty"`
}

type Info struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	CVE         []string `yaml:"cve,omitempty"`
	CWE         []string `yaml:"cwe,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Impact      string   `yaml:"impact,omitempty"` // qué tipo de ataque habilita este hallazgo
}

type HTTPRequest struct {
	Method            string    `yaml:"method"`
	Path              []string  `yaml:"path"`
	MatchersCondition string    `yaml:"matchers-condition,omitempty"`
	Matchers          []Matcher `yaml:"matchers"`
	Evasion           *Evasion  `yaml:"evasion,omitempty"`
	// ForceScheme sobreescribe el esquema (http|https) de la URL construida,
	// ignorando el que traiga BaseURL. Necesario para reglas que deben probar
	// específicamente el comportamiento de HTTP plano (ej. verificar que
	// redirige a HTTPS) sin importar con qué esquema se invocó el scan.
	ForceScheme string `yaml:"force_scheme,omitempty"`
	// NoFollowRedirects evita seguir redirects para esta request puntual y
	// evalúa la respuesta 3xx cruda tal cual llega. Sin esto, el cliente HTTP
	// sigue redirects automáticamente y algunas reglas terminan evaluando el
	// contenido de una página completamente distinta a la solicitada.
	NoFollowRedirects bool `yaml:"no_follow_redirects,omitempty"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
	Negative  bool     `yaml:"negative,omitempty"`
}

type Evasion struct {
	Jitter           string `yaml:"jitter,omitempty"`
	RandomizeHeaders bool   `yaml:"randomize_headers,omitempty"`
}

// TCPRequest define una prueba a nivel TCP crudo: conectar a un puerto,
// enviar datos (opcional) y evaluar la respuesta con los mismos matchers
// que las reglas HTTP. Para protocolos de un solo intercambio, usa `data`.
// Para protocolos con handshake (ej. FTP: banner -> USER -> PASS), usa `steps`.
type TCPRequest struct {
	Port      int       `yaml:"port"`
	Data      string    `yaml:"data,omitempty"`  // atajo: un solo envío (equivale a steps: [{send: data}])
	Steps     []TCPStep `yaml:"steps,omitempty"` // secuencia de envíos, para protocolos con handshake
	Matchers  []Matcher `yaml:"matchers"`
	Condition string    `yaml:"matchers-condition,omitempty"`
	TimeoutMs int       `yaml:"timeout_ms,omitempty"` // default 3000 si es 0
}

// TCPStep es un paso dentro de una secuencia: envía Send (puede ser vacío,
// para solo leer lo que el servidor manda al conectar) y lee la respuesta
// antes de pasar al siguiente paso.
type TCPStep struct {
	Send string `yaml:"send"`
}

type Response struct {
	StatusCode int
	Body       string
	Headers    map[string]string
	TLSVersion string
	Cert       *CertInfo // nil si no es HTTPS o no hubo certificado
	// FinalPath es el path de la URL luego de seguir redirects (si el
	// cliente los siguió). Sirve para detectar cuando un sitio redirige
	// TODO camino a la home ("/") en vez de responder al recurso pedido —
	// en ese caso, evaluar matchers sobre el contenido resultante produce
	// falsos positivos porque nunca se llegó al recurso real.
	FinalPath string
}

// CertInfo resume lo relevante del certificado TLS presentado por el
// servidor, para detectar problemas de configuración (no de vulnerabilidad
// de software) que igual son riesgo real: certs vencidos, auto-firmados,
// o por vencer pronto.
type CertInfo struct {
	Subject      string
	Issuer       string
	NotAfter     time.Time
	SelfSigned   bool
}

type Finding struct {
	RuleID    string
	RuleName  string
	Target    string
	Severity  string
	CVE       []string
	Impact    string
	Timestamp time.Time
	Evidence  string
}
