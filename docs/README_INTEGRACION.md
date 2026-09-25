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
