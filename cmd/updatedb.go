package cmd

import (
	"flag"
	"fmt"
	"time"

	"auditek/internal/cvedb"
	"auditek/internal/ui"
)

// productKeywords mapea nuestros nombres internos de producto a la palabra
// clave que usamos para buscar en NVD (keywordSearch es más permisivo que
// requerir el nombre CPE exacto).
var productKeywords = map[string]string{
	"apache":  "Apache HTTP Server",
	"nginx":   "nginx",
	"openssh": "OpenSSH",
	"iis":     "Microsoft IIS",
	"vsftpd":  "vsftpd",
	"exim":    "Exim",
	"php":     "PHP",
	"jquery":  "jQuery",
}

func runUpdateDBCmd(args []string) error {
	fs := flag.NewFlagSet("update-db", flag.ExitOnError)
	only := fs.String("product", "", "actualizar solo un producto (ej. --product apache); vacío = todos")
	fs.Parse(args)

	targets := productKeywords
	if *only != "" {
		kw, ok := productKeywords[*only]
		if !ok {
			return fmt.Errorf("producto desconocido: %s (opciones: apache, nginx, openssh, iis, vsftpd, exim, php, jquery)", *only)
		}
		targets = map[string]string{*only: kw}
	}

	var all []cvedb.Entry
	i := 0
	for product, keyword := range targets {
		if i > 0 {
			// NVD limita ~5 req/30s sin API key — espaciamos para no chocar el límite.
			fmt.Println("Esperando para respetar el rate limit de NVD...")
			time.Sleep(7 * time.Second)
		}
		i++

		fmt.Printf("Consultando NVD: %s...\n", keyword)
		entries, err := cvedb.FetchFromNVD(keyword, nil)
		if err != nil {
			ui.Warn("error con %s: %v (se omite)", product, err)
			continue
		}
		for idx := range entries {
			entries[idx].Product = product
		}
		fmt.Printf("  %d CVE(s) encontrados\n", len(entries))
		all = append(all, entries...)
	}

	if len(all) == 0 {
		return fmt.Errorf("no se descargó ningún CVE — revisa tu conexión a internet")
	}

	if err := cvedb.SaveCache(all); err != nil {
		return fmt.Errorf("error guardando caché local: %w", err)
	}

	ui.OK("%d CVEs guardados en ~/.auditek/cve-cache.json", len(all))
	return nil
}
