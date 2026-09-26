# Auditek

Escaner de vulnerabilidades gratuito, en línea de comandos, pensado para
PYMEs y para servir como vitrina de servicios de ciberseguridad.

Escanea desde varias perspectivas del negocio: exposición de datos,
misconfiguraciones, cumplimiento básico, y superficie de ataque de
terceros — no solo una lista técnica de CVEs.

## Instalación

Requiere Go 1.22+.

```bash
tar -xzf auditek-mvp.tar.gz
cd auditek-mvp
go mod tidy
go build -o auditek .
```

## Uso rápido

```bash
# Escaneo web (misconfiguraciones + CVEs por fingerprinting de versión)
./auditek scan web https://tusitio.cl

# Escaneo de red (puertos + servicios de protocolo real: Redis, FTP, SMTP...)
./auditek scan network 192.168.1.0/24

# Descubrimiento de subdominios (resolución DNS)
./auditek scan subdomains tusitio.cl

# Análisis estático de un Dockerfile
./auditek scan container ./Dockerfile

# Más detalle en pantalla (-v, -vv, -vvv) y export directo del reporte
./auditek scan web https://tusitio.cl -vv --export html

# Ver el resultado
./auditek report <scan-id>
./auditek report <scan-id> --format html   # reporte con branding, para compartir
```

La salida usa color y una barra de progreso con ETA; el color se desactiva
solo cuando la salida no es una terminal (pipe/redirección), con `NO_COLOR`
o `TERM=dumb`. Con `-v`/`-vv`/`-vvv` se añaden líneas de detalle progresivo.

Antes de cada escaneo (salvo `--stealth`), Auditek pide confirmación de que
tienes autorización sobre el objetivo. Usa `--yes` para saltar el prompt en
scripts/CI.

## Comandos

### `auditek scan [network|web|subdomains|container] <target> [flags]`

Cuatro tipos de escaneo:

- **`network <ip|CIDR>`** — escaneo de puertos + servicios de protocolo real (reglas TCP) + CVEs por banner. Sobre rangos privados activa la confirmación reforzada y marca superficie de movimiento lateral (ver más abajo).
- **`web <url>`** — reglas HTTP (misconfiguraciones, exposición, compliance), CVEs por fingerprint de versión, SRI/supply chain y chequeos de certificado TLS.
- **`subdomains <dominio>`** — enumeración por resolución DNS (ver sección dedicada).
- **`container <Dockerfile|dir>`** — análisis estático de un Dockerfile (malas prácticas y secretos).

| Flag | Default | Aplica a | Qué hace |
|---|---|---|---|
| `--yes` | off | todos | omite la confirmación de autorización |
| `--internal-yes` | off | network | omite la confirmación reforzada de red privada (usar con cuidado) |
| `--ports <spec>` | `top100` | network | `top100`, `80,443`, `1-1000`, o combinado `1-100,8080` |
| `--profile <p>` | `normal` | network | perfil de escaneo: `fast` \| `normal` \| `deep` |
| `--delay <ms>` | 150 | web | pausa entre requests HTTP; `0` = sin límite |
| `--header <val>` | — | web | header custom, repetible (ej. `"Authorization: Bearer xyz"`) |
| `--cookie <val>` | — | web | cookie de sesión (ej. `"session=abc123"`) |
| `--depth <d>` | `normal` | subdomains | `fast` \| `normal` \| `deep` |
| `--focus <cats>` | — | subdomains | categorías separadas por coma (ignora `--depth`) |
| `--wordlist <f>` | — | subdomains | wordlist externa (ignora `--depth`/`--focus`) |
| `--exclude-rule <ids>` | — | network/web | IDs de reglas a omitir, separados por coma |
| `--rules <dir>` | `rules` | network/web | directorio de reglas a cargar en vez del embebido |
| `--exec-hook <f>` | — | network/web | binario externo tuyo cuya salida JSON se integra al reporte (ver más abajo) |
| `--export <fmt>` | — | todos | exporta el reporte sin preguntar: `html` \| `none` (vacío = pregunta interactivamente) |
| `--stealth` | off | network/web | modo evasión avanzado (requiere `--scope` + auth) |
| `--scope <file>` | — | con `--stealth` | scope.yaml del objetivo autorizado |
| `-v` / `-vv` / `-vvv` | off | todos | nivel de detalle: fases + evidencia completa / red y reglas / traza de depuración |

### `auditek report <scan-id> [--format console|json|html]`

Lee un escaneo ya guardado en `~/.auditek/auditek.db` (SQLite) y lo muestra.
El formato `html` genera un archivo `auditek-report-<scan-id>.html` con tu
branding, pensado para enviar a un cliente.

### `auditek auth --token <token>`

Guarda localmente un token JWT (firmado con RSA) que habilita `--stealth`.
El token lo emite quien controla la clave privada (ver `internal/auth/`) —
pensado para consultores que quieren ofrecer una evaluación más profunda a
clientes con contrato.

### `auditek update-db [--product <nombre>]`

Descarga CVEs reales desde la API de NVD y los cachea en
`~/.auditek/cve-cache.json`. Sin esto, solo se usa el set curado a mano
(ver más abajo). Productos soportados: `apache`, `nginx`, `openssh`, `iis`,
`vsftpd`, `exim`, `php`, `jquery`.

NVD limita a ~5 requests/30s sin API key — el comando ya espera entre
productos para respetar ese límite.

## Qué detecta

**21 reglas HTTP** (`rules/exposure/`, `rules/compliance/`, `rules/thirdparty/`):
exposición de secretos (`.env`, backups, claves SSH, `.git/config`, CI/CD),
misconfiguraciones (directory listing, admin panels, phpinfo), cumplimiento
(headers de seguridad, cookies, CSP, HTTPS, ausencia de protección
anti-fuerza-bruta en login), y hallazgos de terceros (subdomain takeover,
errores verbosos).

**5 reglas TCP de protocolo real** (no HTTP): Redis sin auth, Memcached
expuesto, FTP con login anónimo, SMTP con VRFY habilitado, POP3 sin
STARTTLS. El motor soporta protocolos de un solo intercambio y con
handshake multi-paso (`steps:` en el YAML).

**CVEs reales**: fingerprinting de versión vía headers HTTP (`Server`,
`X-Powered-By`) y banners TCP, cruzado contra un set curado de 9 CVEs bien
documentados + lo que traiga `update-db`. Cada hallazgo incluye un campo
**Riesgo** explicando qué tipo de ataque habilita, no solo qué es.

## Escribir tus propias reglas

```yaml
id: mi-regla
info:
  name: "Nombre legible"
  severity: medium   # info | low | medium | high | critical
  cwe: ["CWE-200"]
  description: "Qué detecta"
  impact: "Qué le permite hacer a un atacante"
type: http            # http | tcp
http:
  - method: GET
    path: ["{{BaseURL}}/ruta"]
    matchers-condition: and   # and | or
    matchers:
      - type: status           # status | word | regex | size
        status: [200]
      - type: word
        part: body              # body | header
        words: ["texto a buscar"]
        negative: false          # true = matchea si NO está presente
```

Para reglas `type: tcp`, ver `rules/exposure/redis-unauthenticated.yaml`
(un solo intercambio) y `rules/exposure/ftp-anonymous-login.yaml`
(handshake multi-paso con `steps:`).

Guarda tus reglas en un directorio propio y usa `--rules <dir>` para
cargarlas en vez de (no junto a) las embebidas.

## Riesgo de supply chain (SRI)

Auditek revisa cada `<script src="...">` que cargue desde un origen
DISTINTO al del sitio (típicamente una CDN de terceros) y marca los que no
tengan el atributo `integrity` (Subresource Integrity). Sin SRI, si esa
CDN se compromete alguna vez, el script se ejecuta en el sitio sin
ninguna verificación — el mecanismo detrás de varios compromisos de
supply chain reales que afectaron miles de sitios a la vez.

Scripts del mismo origen o con rutas relativas no se marcan — el riesgo
que SRI mitiga es específicamente confiar en infraestructura de terceros,
no en el propio servidor.

## Riesgo de supply chain

**SRI en scripts externos** (ver arriba): scripts de terceros sin
`integrity` — si esa CDN se compromete, el sitio ejecuta lo que sea sin
verificación.

**Dependencias con versión suelta**: si `package.json`/`composer.json`
está expuesto (por la regla de exposición), Auditek además parsea el
manifiesto y marca constraints como `^1.2.3`, `~1.2.3`, `*`, o `latest` —
cualquier versión futura se instalaría sin revisión.

**CVEs en dependencias declaradas**: la versión de cada dependencia se
cruza contra la CVE db (mismo motor que usa fingerprinting de servidor).
Es una aproximación: el constraint declarado (`^3.4.0`) no garantiza que
la versión REALMENTE instalada sea esa — el hallazgo lo aclara.

**Archivos de CI/CD expuestos**: `.gitlab-ci.yml`, `.travis.yml`,
`.circleci/config.yml`, `Jenkinsfile`, y varios paths comunes de GitHub
Actions — revelan la topología del pipeline y a veces secretos mal
manejados.

## Chequeos de certificado TLS

Además de la versión de TLS (obsoleta = TLSv1.0/1.1), Auditek revisa el
certificado presentado y reporta:
- **Auto-firmado** (`tls-cert-self-signed`, medio) — Subject e Issuer coinciden
- **Vencido** (`tls-cert-expired`, alto)
- **Por vencer** en menos de 30 días (`tls-cert-expiring-soon`, bajo)

Nota: el escaneo en sí acepta cualquier certificado (`InsecureSkipVerify`)
para no fallar el scan completo por un cert problemático — pero ahora
**reporta** el problema como hallazgo en vez de ignorarlo silenciosamente.

## Escanear sitios que requieren login

Por defecto, `scan web` solo ve lo que un visitante anónimo vería. Para
escanear rutas que requieren sesión iniciada (paneles internos, áreas de
cliente, APIs autenticadas), pasa la cookie de sesión o el header de auth:

```bash
auditek scan web https://app.tucliente.cl --cookie "session=abc123"
auditek scan web https://app.tucliente.cl --header "Authorization: Bearer eyJhbGc..."
auditek scan web https://app.tucliente.cl --header "X-Api-Key: xyz" --cookie "session=abc123"
```

`--header` es repetible (podés pasarlo varias veces). Un header mal
formado (sin `:`) se ignora con un aviso, no aborta el escaneo completo.

## Descubrimiento de subdominios

```bash
auditek scan subdomains tucliente.cl                          # default: profundidad "normal"
auditek scan subdomains tucliente.cl --depth fast               # rápido, solo lo más común
auditek scan subdomains tucliente.cl --depth deep                # más categorías, más lento
auditek scan subdomains tucliente.cl --focus admin,dev           # solo estas categorías, ignora --depth
auditek scan subdomains tucliente.cl --wordlist seclist.txt      # archivo externo, ignora --depth y --focus
```

Resolución DNS pura (`net.LookupHost`) — no se conecta a nada. La wordlist
embebida está organizada por categoría, para acotar el escaneo a lo que
realmente interesa en vez de tirar siempre todo:

| Categoría | Ejemplos | fast | normal | deep |
|---|---|---|---|---|
| `admin` | admin, panel, cpanel, phpmyadmin | ✅ | ✅ | ✅ |
| `dev` | dev, staging, test, qa, uat | ✅ | ✅ | ✅ |
| `infra` | mail, smtp, ns1, ftp | ✅ | ✅ | ✅ |
| `remote-access` | vpn, rdp, ssh, proxy | — | ✅ | ✅ |
| `devops` | jenkins, gitlab, jira | — | ✅ | ✅ |
| `web` | www, cdn, api, blog | — | ✅ | ✅ |
| `sensitive` | secure, vault, backup, internal | — | — | ✅ |
| `data` | db, mysql, redis, mongo | — | — | ✅ |

`--wordlist <archivo>` acepta cualquier lista externa (una entrada por
línea, `#` para comentarios) — para usar algo tipo SecLists con miles de
entradas sin embeberlo en el binario.

Si un subdominio resuelve a una **IP privada** (192.168.x, 10.x), Auditek
lo marca explícitamente — puede ser una filtración de topología de red
interna vía DNS público mal configurado.

**Limitación**: incluso en `deep`, sigue siendo una wordlist curada
(~75 entradas) — no reemplaza fuentes reales de descubrimiento masivo
como Certificate Transparency logs.

## Integrar resultados de otras herramientas (`auditek import`)

Auditek es intencionalmente pasivo y no hace explotación activa (ver
sección de límites al final). Si desarrollás una herramienta separada
para eso — pentesting con explotación real, bajo tu propio criterio y
autorización — podés integrar sus resultados en los mismos
reportes/correlación de Auditek sin que este proyecto contenga ni ejecute
nada de esa lógica. El punto de unión es un formato JSON simple:

```bash
auditek import resultados.json --target 192.168.1.50 --source mi-herramienta
```

`resultados.json` es un array de objetos con este contrato:

```json
[
  {
    "rule_id": "confirmed-rce-cve-2021-41773",
    "rule_name": "RCE confirmada explotando CVE-2021-41773",
    "target": "192.168.1.50:80",
    "severity": "critical",
    "cve": "CVE-2021-41773",
    "impact": "Descripción de lo que se logró",
    "evidence": "Evidencia concreta"
  }
]
```

Campos obligatorios: `rule_id`, `rule_name`, `target`, `severity`
(`info|low|medium|high|critical`). `cve`, `impact`, `evidence` son
opcionales. Hallazgos mal formados se omiten con un aviso — no rompen la
importación completa.

Los hallazgos importados pasan por el **mismo motor de correlación** que
los nativos — si un `rule_id` coincide con un patrón conocido (ej. un CVE
crítico confirmado junto con superficie de movimiento lateral detectada
por Auditek en el mismo scan), se arma la narrativa de escalada
automáticamente, igual que con hallazgos propios.

Esto significa: tu herramienta de pentesting vive en su propio repo, con
su propio código de explotación, mantenida por vos — Auditek solo sabe
leer el resultado final.

### Invocación automática durante el scan (`--exec-hook`)

Si preferís que Auditek llame a tu herramienta automáticamente en vez de
correr `import` a mano después:

```bash
auditek scan web https://cliente.cl --exec-hook /ruta/a/tu-herramienta
auditek scan network 192.168.1.0/24 --exec-hook /ruta/a/tu-herramienta
```

Auditek ejecuta `tu-herramienta <target>` al final del scan pasivo, y
espera que tu programa imprima en **stdout** el mismo array JSON descrito
arriba (`rule_id`, `rule_name`, `target`, `severity`, ...). Lo que haga
tu programa por dentro —incluida cualquier lógica de explotación— es
enteramente tuyo; Auditek solo ejecuta el binario que vos indiques
explícitamente (nunca uno por defecto, nunca descargado) y parsea su
salida. Si tu herramienta falla o devuelve algo que no es JSON válido, el
scan avisa y sigue solo con los hallazgos nativos — un hook roto nunca
tumba el scan completo.

Los hallazgos que aporte tu herramienta pasan por la misma correlación
que los nativos, igual que con `import`.

## "Hasta dónde podría llegar" — correlación de hallazgos

Cada hallazgo individual tiene su propio campo Riesgo, pero algunos
hallazgos **combinados** representan un salto de riesgo mayor a la suma de
sus partes — ej. credenciales expuestas + panel de administración
accesible no es "dos problemas medios", es un camino directo a control
administrativo. Auditek detecta estas combinaciones dentro de un mismo
escaneo y agrega un hallazgo adicional (`path-*`) con la narrativa
completa, pensado para explicarle al cliente el impacto real en vez de
una lista plana de CVEs.

**Importante: esto sigue siendo 100% pasivo.** La narrativa es una
hipótesis basada en hallazgos ya confirmados por separado — Auditek nunca
ejecuta la cadena, nunca prueba si Redis realmente permite escribir una
clave SSH, nunca intenta el pivote. Solo explica qué *podría* pasar si
alguien encadenara esos hallazgos.

Patrones actuales: Redis sin auth + superficie de movimiento lateral
(persistencia → pivote), secretos expuestos + panel admin (credenciales →
acceso administrativo), CVE crítico + superficie de movimiento lateral
(compromiso inicial → propagación). Ver `internal/correlate/correlate.go`
para agregar más patrones.

**Limitación**: la correlación solo cruza hallazgos dentro del mismo
scan — no correlaciona un `scan web` con un `scan network` hechos por
separado, aunque apunten al mismo cliente.

## Escaneo de redes internas (movimiento lateral/vertical)

Si el target de `scan network` cae dentro de un rango de red privada
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback), Auditek detecta
que el escaneo se está haciendo **desde dentro** de esa red — el mismo
contexto que precede a una evaluación de movimiento lateral — y exige una
confirmación reforzada distinta a la genérica: hay que escribir la palabra
exacta `AUTORIZADO`, no basta con `s`/`y`. Queda registro local en
`~/.auditek/internal-scan-audit.log` con timestamp y target confirmado.

Para automatizar esto en CI/scripts de forma deliberada (nunca por accidente
vía el `--yes` genérico), usa `--internal-yes`.

Sobre redes internas, Auditek también marca con severidad elevada los
puertos de gestión remota típicos de movimiento lateral (RDP 3389, WinRM
5985/5986, SMB 445, SSH 22) bajo el hallazgo `lateral-movement-surface` —
**esto es detección pasiva únicamente**: solo reporta que el puerto está
abierto y por qué eso importa en un contexto interno, nunca intenta
autenticarse, explotar, ni moverse a otro host. Auditek no hace ni hará
explotación activa ni post-explotación (eso es un tipo de servicio
distinto, típicamente con operador humano y herramientas especializadas).

## Modo stealth (evasión avanzada)

Pensado como gancho de venta: la versión gratis encuentra vulnerabilidades,
`--stealth` sirve para evaluar si el SOC del cliente se daría cuenta.

Requiere:
1. Un token JWT válido (`auditek auth --token ...`), emitido por quien
   controla la clave privada — ver `internal/auth/keys/public.pem`
2. Un `scope.yaml` declarando el objetivo autorizado:

```yaml
authorized_by: "Nombre de quien autoriza"
date_signed: "2026-09-19"
targets:
  - domain: "cliente.cl"
    subdomains: true
excluded:
  - "produccion-critica.cliente.cl"
```

Sin ambos, `--stealth` falla antes de enviar un solo paquete.

## Limitaciones conocidas (honesto, no vendido de más)

- **CVE db pequeña**: 9 entradas curadas a mano. `update-db` la expande vía
  NVD, pero la cobertura real de tu stack específico puede seguir siendo baja.
- **`scan container` es análisis estático** — parsea el Dockerfile en busca de
  malas prácticas y secretos; no construye ni inspecciona la imagen resultante
  ni sus capas.
- **Sin protocolo binario** (MongoDB, MySQL) — el motor TCP solo soporta
  protocolos de texto plano por ahora.
- El target sin protocolo explícito (`scan web midominio.cl` sin `http://`)
  asume `https://` — si tu sitio es HTTP plano, especifica el protocolo.
- `http-not-redirecting-https` puede dar falso positivo si el sitio ya es
  HTTPS (la regla solo verifica que la URL responda 200).

## Estructura del proyecto

```
cmd/            comandos CLI (auth, scan, report, update-db, import) + display
internal/
  engine/       motor de reglas HTTP + TCP, matchers, fingerprinting, SRI, supply chain
  cvedb/        base de datos curada + cliente NVD
  netscan/      escaneo de puertos, perfiles, rangos/CIDR, detección de CDN
  subdomain/    enumeración de subdominios por DNS
  container/    análisis estático de Dockerfile
  correlate/    correlación de hallazgos ("hasta dónde podría llegar")
  scope/        validación de scope.yaml para modo stealth
  auth/         JWT para modo stealth
  findings/     persistencia SQLite
  report/       generación de reportes HTML
  progress/     barra de progreso de la terminal
  ui/           estilo de la salida en terminal (color, badges, verbose)
rules/          reglas YAML (exposure/, compliance/, thirdparty/)
exploits/       módulos externos opcionales para --exec-hook (binarios separados)
```
