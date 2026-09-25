# Pack de integración — PoC externa + correlación

Compatible con el repo real: https://github.com/ligarius/auditek

## Contenido

| Ruta | Qué es |
|------|--------|
| `exploits/redis-unauth/main.go` | Módulo externo: PoC Redis → JSON para `import` / `--exec-hook` |
| `patches/correlate_pathrules_addition.go.txt` | Reglas nuevas para pegar en `internal/correlate/correlate.go` |

## 1. Parche del correlator

1. Abre `internal/correlate/correlate.go` en el repo Auditek.
2. Localiza `var pathRules = []PathRule{ ... }`
3. Pega el contenido de `patches/correlate_pathrules_addition.go.txt` **antes** del cierre `}` del slice.
4. Recompila:

```bash
go build -o auditek .
```

## 2. Compilar el módulo Redis

```bash
cd exploits/redis-unauth
go build -o redis-unauth .
```

Solo stdlib; no hace falta `go.mod` aparte si compilas desde esa carpeta con un archivo.

## 3. Uso con Auditek

```bash
# Opción A — mismo scan (recomendado para path combinados)
./auditek scan network 127.0.0.1 --yes --exec-hook /ruta/a/redis-unauth

# Opción B — import
./redis-unauth 127.0.0.1:6379 > /tmp/redis-poc.json
./auditek import /tmp/redis-poc.json --target 127.0.0.1:6379 --source redis-unauth
./auditek report <scan-id>
```

## 4. rule_id que emite el módulo

- `redis-write-demonstrated` → activa `path-redis-write-confirmed`
- Si el scan nativo también tiene `redis-unauthenticated` → `path-redis-detected-and-write-confirmed`

## 5. Lab rápido

```bash
docker run -d --name auditek-redis -p 6379:6379 redis:7 --protected-mode no
# ... comandos de arriba ...
docker rm -f auditek-redis
```

## 6. Subir a GitHub

Copia estas carpetas/archivos a tu clon de `ligarius/auditek`, luego:

```bash
git add internal/correlate/correlate.go exploits/
git commit -m "feat: correlación PoC externa y módulo redis-unauth para exec-hook"
git push origin main
```

No subas el binario compilado; solo el `.go`.

## 7. Módulo `secrets-validate` (emisor de `secrets-validated`)

`exploits/secrets-validate/` es un segundo módulo externo (solo stdlib). Descarga
los archivos de secretos típicos del objetivo (`.env`, backups de `wp-config`,
`.git/config`, etc.) y **valida estáticamente** si contienen material de alto
valor (claves live de Stripe/AWS/Google/Slack/GitHub, llaves privadas PEM, URIs
de BD con credenciales o tokens de alta entropía). Emite el `rule_id`
`secrets-validated` con la evidencia **redactada**.

> Alcance deliberado: la validación es **estática** (formato/patrón). El módulo
> **no** usa ni autentica las credenciales contra ningún servicio — eso sería
> intrusivo y, sin autorización específica, indebido. "Validado" = material
> accionable de alto valor presente, no credencial probada.

Compilar y usar:

```bash
cd exploits/secrets-validate && go build -o secrets-validate .

# como hook del mismo scan web
./auditek scan web http://localhost:8080 --yes --exec-hook ./exploits/secrets-validate/secrets-validate
```

`rule_id` que emite y correlación que activa:

- `secrets-validated` → activa `path-secrets-validated`.
- Si el scan nativo también encontró `exposed-env-file` / `exposed-wp-config-bak` /
  `exposed-git-config` → `path-secrets-detected-and-validated`.
