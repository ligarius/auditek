package netscan

import "time"

type ScanProfile struct {
	Name        string
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	Description string
}

func GetProfile(name string) ScanProfile {
	switch name {
	case "fast":
		return ScanProfile{
			Name:        "fast",
			Ports:       getTopPorts(20),
			Concurrency: 200,
			Timeout:     1 * time.Second,
			Description: "20 puertos más comunes, timeout corto, alta concurrencia",
		}
	case "deep":
		return ScanProfile{
			Name:        "deep",
			Ports:       getAllPorts(),
			Concurrency: 50,
			Timeout:     5 * time.Second,
			Description: "Todos los puertos (65535), timeout largo, baja concurrencia para no saturar",
		}
	default: // "normal"
		return ScanProfile{
			Name:        "normal",
			Ports:       getTopPorts(100),
			Concurrency: 100,
			Timeout:     2 * time.Second,
			Description: "Top 100 puertos, balance de velocidad y cobertura",
		}
	}
}

func getTopPorts(count int) []int {
	// Puertos más comunes por densidad de servicios
	common := []int{
		80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 6379, 27017,
		8000, 8080, 8443, 3389, 445, 139, 135, 5985, 5986, 9200, 9300,
		5900, 5901, 3389, 23, 69, 161, 162, 389, 636, 1433, 1521,
		3050, 5432, 5984, 6379, 7000, 7001, 8086, 8161, 8888, 9042,
		9160, 9200, 11211, 27017, 27018, 28017, 50070, 8020,
		// More common: HTTP/HTTPS derivatives
		8001, 8002, 8003, 8008, 8081, 8082, 8085, 8090, 8444,
		// SSH derivatives
		2222, 2200,
		// Databases
		5433, 5434, 27018, 27019, 27020,
		// Reverse shells / backdoors
		4444, 4445, 4446, 5555, 6666, 7777, 8888, 9999,
		// Other services
		111, 113, 123, 135, 139, 179, 199, 389, 427, 465, 514,
		587, 636, 993, 995, 1025, 1026, 1027, 1028, 1029, 1433,
		1521, 3306, 3389, 5432, 5984, 6379, 7000, 8086, 8161,
		9160, 9200, 11211, 27017, 50070, 8020, 8086,
	}
	common = dedupePorts(common)
	if count >= len(common) {
		return common
	}
	return common[:count]
}

func getAllPorts() []int {
	ports := make([]int, 0, 65535)
	for i := 1; i <= 65535; i++ {
		ports = append(ports, i)
	}
	return ports
}

// dedupePorts devuelve los puertos sin repetidos, preservando el orden de
// primera aparición. Evita que una lista con duplicados (perfiles, --ports,
// rangos) haga que ScanHost escanee y reporte el mismo puerto más de una vez.
func dedupePorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
