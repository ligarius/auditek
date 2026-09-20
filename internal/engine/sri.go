package engine

import (
	"net/url"
	"regexp"
	"strings"
)

// scriptTagRe captura cada tag <script ...> completo (sus atributos) para
// poder revisar src= e integrity= dentro del mismo tag, sin confundir
// atributos de un script con los de otro.
var scriptTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
var srcAttrRe = regexp.MustCompile(`(?is)\bsrc\s*=\s*["']([^"']+)["']`)
var integrityAttrRe = regexp.MustCompile(`(?is)\bintegrity\s*=`)

// FindExternalScriptsWithoutSRI busca <script src="..."> que apunten a un
// origen DISTINTO al del sitio (ej. una CDN de terceros) y no tengan el
// atributo integrity. Si esa CDN se compromete alguna vez, el sitio
// ejecutaría lo que sea que el atacante ponga ahí sin ninguna verificación
// — es exactamente el vector de varios ataques de supply chain conocidos.
//
// Scripts del mismo origen o relativos (ej. src="/js/app.js") se omiten:
// el riesgo que SRI mitiga es específicamente confiar en infraestructura
// de un tercero, no en el propio servidor.
func FindExternalScriptsWithoutSRI(body, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	baseHost := base.Hostname()

	var missing []string
	seen := map[string]bool{}

	for _, tagMatch := range scriptTagRe.FindAllStringSubmatch(body, -1) {
		attrs := tagMatch[1]

		srcMatch := srcAttrRe.FindStringSubmatch(attrs)
		if srcMatch == nil {
			continue // script sin src (inline) — SRI no aplica
		}
		src := srcMatch[1]

		if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") && !strings.HasPrefix(src, "//") {
			continue // relativo -> mismo origen, no es el riesgo que buscamos
		}

		scriptURL, err := url.Parse(src)
		if err != nil {
			continue
		}
		if scriptURL.Hostname() == baseHost {
			continue // mismo host aunque sea URL absoluta -> no es de terceros
		}

		if !integrityAttrRe.MatchString(attrs) {
			if !seen[src] {
				seen[src] = true
				missing = append(missing, src)
			}
		}
	}

	return missing
}
