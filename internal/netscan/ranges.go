package netscan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ExpandHosts(target string) ([]string, error) {
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}
	if strings.Contains(target, "-") {
		return expandRange(target)
	}
	return []string{target}, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("CIDR inválido: %w", err)
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		dup := make(net.IP, len(ip))
		copy(dup, ip)
		ips = append(ips, dup.String())
	}

	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func expandRange(r string) ([]string, error) {
	lastDot := strings.LastIndex(r, ".")
	if lastDot == -1 {
		return nil, fmt.Errorf("formato de rango inválido")
	}
	base := r[:lastDot]
	parts := strings.Split(r[lastDot+1:], "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("formato de rango inválido, esperado: x.x.x.START-END")
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	var ips []string
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("%s.%d", base, i))
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ParsePorts(spec string) ([]int, error) {
	if spec == "top100" {
		return top100Ports, nil
	}

	var ports []int
	for _, part := range strings.Split(spec, ",") {
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, err
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

var top100Ports = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1723, 3306, 3389, 5900, 8000, 8080, 8443, 8888, 9200, 27017, 6379, 5432,
}

// privateRanges son los bloques RFC1918 (redes privadas) + loopback + link-local.
// Un target dentro de estos rangos implica que el escaneo se hace DESDE dentro
// de esa red (no es un sitio público) — señal de que se está evaluando
// movimiento lateral/vertical, que requiere un nivel de autorización distinto.
var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
	} {
		_, ipNet, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, ipNet)
	}
}

// IsPrivateTarget determina si un host (IP o rango) cae dentro de un bloque
// de red privada/interna. Para un target que no es una IP literal (dominio,
// CIDR), intenta parsear igual — si no se puede determinar, devuelve false
// (es decir, se trata como escaneo externo por defecto, no al revés, para
// no bloquear accidentalmente escaneos legítimos a dominios públicos).
func IsPrivateTarget(target string) bool {
	// Si es un CIDR, revisamos la IP base
	if strings.Contains(target, "/") {
		ip, _, err := net.ParseCIDR(target)
		if err != nil {
			return false
		}
		return isPrivateIP(ip)
	}
	// Si es un rango tipo x.x.x.1-10, revisamos el prefijo de red
	base := target
	if idx := strings.LastIndex(target, "-"); idx != -1 && strings.Contains(target[:idx], ".") {
		lastDot := strings.LastIndex(target[:idx], ".")
		base = target[:lastDot] + ".0"
	}
	ip := net.ParseIP(base)
	if ip == nil {
		// no es una IP literal (podría ser dominio) — no lo tratamos como interno
		return false
	}
	return isPrivateIP(ip)
}

func isPrivateIP(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
