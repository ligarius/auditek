package netscan

import "net"

// cdnRanges cataloga bloques IP publicados oficialmente por proveedores de
// CDN/proxy inverso (Cloudflare, Fastly). Estos proveedores terminan la
// conexión TCP en su borde anycast — un puerto que aparece "abierto" en una
// IP de estos rangos no implica necesariamente que haya un servicio real
// escuchando detrás, salvo que el proveedor tenga passthrough L4 explícito
// (ej. Cloudflare Spectrum) configurado para ese puerto. Sin eso, el borde
// acepta el handshake TCP pero nunca reenvía datos a un backend, por lo que
// nunca llega un banner de aplicación (FTP, SMTP, etc.).
type cdnRange struct {
	provider string
	ipNet    *net.IPNet
}

var cdnRanges []cdnRange

func init() {
	registerCDNRanges("Cloudflare", cloudflareCIDRs)
	registerCDNRanges("Fastly", fastlyCIDRs)
}

func registerCDNRanges(provider string, cidrs []string) {
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		cdnRanges = append(cdnRanges, cdnRange{provider: provider, ipNet: ipNet})
	}
}

// DetectCDNProvider indica si ip pertenece a un rango publicado de un
// proveedor de CDN/proxy conocido.
func DetectCDNProvider(ip net.IP) (provider string, ok bool) {
	if ip == nil {
		return "", false
	}
	for _, r := range cdnRanges {
		if r.ipNet.Contains(ip) {
			return r.provider, true
		}
	}
	return "", false
}

// ResolveCDNProvider resuelve host (dominio o IP literal) y devuelve el
// proveedor CDN/proxy detectado si alguna de sus IPs resueltas cae dentro
// de un rango conocido. Un error de resolución o ausencia de match
// devuelve ("", false) — no bloquea el flujo del caller.
func ResolveCDNProvider(host string) (provider string, ok bool) {
	if ip := net.ParseIP(host); ip != nil {
		return DetectCDNProvider(ip)
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", false
	}
	for _, s := range ips {
		if provider, ok := DetectCDNProvider(net.ParseIP(s)); ok {
			return provider, true
		}
	}
	return "", false
}

// Rangos oficiales publicados por cada proveedor. Cloudflare:
// https://www.cloudflare.com/ips-v4 y /ips-v6. Fastly:
// https://api.fastly.com/public-ip-list. Estos bloques cambian con poca
// frecuencia pero pueden quedar desactualizados con el tiempo.
var cloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

var fastlyCIDRs = []string{
	"23.235.32.0/20",
	"43.249.72.0/22",
	"103.244.50.0/24",
	"103.245.222.0/23",
	"103.245.224.0/24",
	"104.156.80.0/20",
	"140.248.64.0/18",
	"140.248.128.0/17",
	"146.75.0.0/17",
	"151.101.0.0/16",
	"157.52.64.0/18",
	"167.82.0.0/17",
	"167.82.128.0/20",
	"167.82.160.0/20",
	"167.82.224.0/20",
	"172.111.64.0/18",
	"185.31.16.0/22",
	"199.27.72.0/21",
	"199.232.0.0/16",
	"2a04:4e40::/32",
	"2a04:4e42::/32",
}
