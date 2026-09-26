package cmd

import (
	"fmt"
	"os"
)

func Execute() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "auth":
		err = runAuthCmd(os.Args[2:])
	case "scan":
		err = runScanCmd(os.Args[2:])
	case "report":
		err = runReportCmd(os.Args[2:])
	case "update-db":
		err = runUpdateDBCmd(os.Args[2:])
	case "import":
		err = runImportCmd(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Printf("comando no reconocido: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Auditek — escaneo de vulnerabilidades para PYMEs

Uso:
  auditek auth --token <token>
  auditek scan [network|web|subdomains|container] <target> [flags]
  (para container, <target> es un Dockerfile o un directorio que lo contenga)
  auditek report <scan-id> [flags]
  auditek update-db [--product <nombre>]
  auditek import <archivo.json> [--target <target>]

Flags de scan:
  --stealth        modo evasión (requiere --scope y auth)
  --scope <file>   archivo scope.yaml
  --yes            omite la confirmación de autorización
  --delay <ms>     pausa entre requests, en ms (default 150, 0 = sin límite)
  --ports <spec>   solo scan network: top100 | 80,443 | 1-1000 (default top100)
  --exclude-rule <ids>  IDs de reglas a omitir, separados por coma
  --rules <dir>    directorio de reglas a cargar (default: rules)
  --internal-yes   omite la confirmación reforzada para redes privadas (usar con cuidado)
  --header <val>   header custom, repetible (solo scan web), ej. "Authorization: Bearer xyz"
  --cookie <val>   cookie de sesión (solo scan web), ej. "session=abc123"
  --depth <val>    solo scan subdomains: fast | normal | deep (default normal)
  --focus <cats>   solo scan subdomains: categorías separadas por coma (admin,dev,infra,remote-access,devops,web,sensitive,data)
  --wordlist <f>   solo scan subdomains: archivo externo, ignora --depth/--focus
  --ct             solo scan subdomains: además consulta Certificate Transparency (crt.sh)
  --osv            solo scan web: consulta OSV (osv.dev) por CVEs de dependencias en manifiestos expuestos
  --exec-hook <f>  ruta a un programa externo tuyo; su salida JSON se integra al reporte (ver README)
  --export <fmt>   exporta el reporte sin preguntar: html | none (vacío = pregunta)
  -v | -vv | -vvv  nivel de detalle: fases/evidencia | red y reglas | traza de depuración

Salida:
  El color se desactiva solo si la salida no es una terminal, con NO_COLOR o TERM=dumb.

Flags de report:
  --format <fmt>   console|json|html`)
}
