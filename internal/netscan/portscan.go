package netscan

import (
	"net"
	"strconv"
	"sync"
	"time"
)

type PortResult struct {
	Host    string
	Port    int
	Open    bool
	Service string
	Banner  string
}

type ScanOptions struct {
	Timeout     time.Duration
	Concurrency int
	ProgressFn  func(completed, total int) // Callback para mostrar progreso
}

func DefaultOptions() ScanOptions {
	return ScanOptions{
		Timeout:     2 * time.Second,
		Concurrency: 100,
		ProgressFn:  nil,
	}
}

func ScanHost(host string, ports []int, opts ScanOptions) []PortResult {
	var results []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, opts.Concurrency)
	completed := 0
	total := len(ports)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			r := scanPort(host, p, opts.Timeout)
			if r.Open {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}

			// Actualizar progreso
			if opts.ProgressFn != nil {
				mu.Lock()
				completed++
				opts.ProgressFn(completed, total)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

func scanPort(host string, port int, timeout time.Duration) PortResult {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return PortResult{Host: host, Port: port, Open: false}
	}
	defer conn.Close()

	banner := grabBanner(conn, timeout)
	service := IdentifyService(port, banner)

	return PortResult{
		Host:    host,
		Port:    port,
		Open:    true,
		Service: service,
		Banner:  banner,
	}
}

func grabBanner(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

func ScanMultipleHosts(hosts []string, ports []int, opts ScanOptions) map[string][]PortResult {
	results := make(map[string][]PortResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	hostSem := make(chan struct{}, 10)

	for _, host := range hosts {
		wg.Add(1)
		hostSem <- struct{}{}

		go func(h string) {
			defer wg.Done()
			defer func() { <-hostSem }()

			r := ScanHost(h, ports, opts)
			if len(r) > 0 {
				mu.Lock()
				results[h] = r
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return results
}
