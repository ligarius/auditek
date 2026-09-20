# Auditek - Changelog

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
