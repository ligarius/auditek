# Auditek - Changelog

## [0.3.0] - 2026-09-26

### Agregado
- **Escaneo de red interno / movimiento lateral**: sobre rangos privados
  (10/8, 172.16/12, 192.168/16, loopback) se exige confirmación reforzada
  (`AUTORIZADO`) con registro local, y se marca la superficie de gestión
  remota (RDP/WinRM/SMB/SSH) como `lateral-movement-surface` — detección
  pasiva, sin autenticar ni explotar. `--internal-yes` para automatizar.
- **`scan subdomains`**: enumeración por resolución DNS con wordlist embebida
  por categoría (`--depth`, `--focus`) o externa (`--wordlist`); marca los
  subdominios que resuelven a IP privada.
- **`scan container`**: análisis estático de Dockerfile (malas prácticas y
  secretos).
- **`auditek import` + `--exec-hook`**: integra la salida JSON de una
  herramienta externa tuya (contrato `ExternalFinding`) en los mismos
  reportes y correlación. Auditek solo ejecuta el binario que indiques y lee
  su stdout; nunca contiene ni descarga lógica de explotación.
- **Módulos `exploits/` (opcionales, binarios separados, solo vía `--exec-hook`)**:
  `redis-unauth`, `secrets-validate`, `lateral-probe` (confirma WinRM/RDP; con
  modos `--query` e `--interactive`), y `vsftpd-backdoor` (CVE-2011-2523, con
  modos verificación / `--cmd` / `--shell`).
- **`--export html|none`**: exporta el reporte sin el prompt interactivo.
- **Salida en pantalla renovada** (`internal/ui`): colores ANSI, badges de
  severidad, barra de progreso con ETA, fases `▶/✓`, y verbose `-v/-vv/-vvv`.
  El color se desactiva solo sin terminal, con `NO_COLOR` o `TERM=dumb`.
- **Correlación de hallazgos** (`internal/correlate`): agrega hallazgos
  `path-*` con la narrativa de escalada a partir de hallazgos ya confirmados
  (100% hipotético, nunca ejecuta la cadena).

### Corregido
- La documentación indicaba que `scan container` no estaba implementado; sí lo
  está (análisis estático de Dockerfile).

## [0.2.0] - 2026-09-20

### Mejorado
- **httpscan.go**: Rechazar falsos positivos por redirects (3xx)
  - Agregada función `isRedirect()` para filtrar status codes 3xx
  - Las rutas que devuelven 301/302 ya no se reportan como vulnerabilidades
  - Solo se analizan rutas que devuelven 2xx (realmente accesibles)

### Mejorado
- **httpscan.go**: Feedback en tiempo real durante escaneo
  - Muestra progreso de reglas procesadas
  - Desglose de hallazgos por severidad al final

## [0.1.0] - 2026-09-15
- MVP inicial de Auditek
