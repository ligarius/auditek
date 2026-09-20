package engine

import "testing"

func TestEvaluateMatchersStatus(t *testing.T) {
	resp := &Response{StatusCode: 200}
	m := []Matcher{{Type: "status", Status: []int{200, 301}}}
	if !EvaluateMatchers(m, "", resp) {
		t.Error("esperaba match de status 200")
	}

	resp.StatusCode = 404
	if EvaluateMatchers(m, "", resp) {
		t.Error("no esperaba match de status 404")
	}
}

func TestEvaluateMatchersWordOr(t *testing.T) {
	resp := &Response{Body: "Welcome to Apache Server"}
	m := []Matcher{{Type: "word", Words: []string{"nginx", "Apache"}, Condition: "or"}}
	if !EvaluateMatchers(m, "", resp) {
		t.Error("esperaba match por condición 'or' con al menos una palabra presente")
	}
}

func TestEvaluateMatchersWordAnd(t *testing.T) {
	resp := &Response{Body: "Welcome to Apache Server"}
	m := []Matcher{{Type: "word", Words: []string{"Apache", "nginx"}, Condition: "and"}}
	if EvaluateMatchers(m, "", resp) {
		t.Error("no esperaba match: 'nginx' no está presente y la condición es 'and'")
	}
}

func TestEvaluateMatchersRegex(t *testing.T) {
	resp := &Response{Body: "version=1.2.3"}
	m := []Matcher{{Type: "regex", Regex: []string{`version=\d+\.\d+\.\d+`}}}
	if !EvaluateMatchers(m, "", resp) {
		t.Error("esperaba match de regex")
	}
}

func TestEvaluateMatchersRegexInvalidPatternSkipped(t *testing.T) {
	resp := &Response{Body: "anything"}
	m := []Matcher{{Type: "regex", Regex: []string{"(["}}} // patrón inválido
	if EvaluateMatchers(m, "", resp) {
		t.Error("un patrón regex inválido no debería producir match")
	}
}

func TestEvaluateMatchersSize(t *testing.T) {
	resp := &Response{Body: "12345"}
	m := []Matcher{{Type: "size", Words: []string{"5"}}}
	if !EvaluateMatchers(m, "", resp) {
		t.Error("esperaba match de tamaño exacto")
	}

	resp.Body = "1234"
	if EvaluateMatchers(m, "", resp) {
		t.Error("no esperaba match: el tamaño no coincide")
	}
}

func TestEvaluateMatchersNegative(t *testing.T) {
	resp := &Response{Body: "no error here"}
	m := []Matcher{{Type: "word", Words: []string{"error 500"}, Negative: true}}
	if !EvaluateMatchers(m, "", resp) {
		t.Error("esperaba match negativo: la palabra no está presente")
	}
}

func TestEvaluateMatchersConditionAndAcrossMatchers(t *testing.T) {
	resp := &Response{StatusCode: 200, Body: "OK"}
	m := []Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "word", Words: []string{"OK"}},
	}
	if !EvaluateMatchers(m, "and", resp) {
		t.Error("esperaba match: ambos matchers cumplen")
	}

	m[1].Words = []string{"FAIL"}
	if EvaluateMatchers(m, "and", resp) {
		t.Error("no esperaba match: uno de los matchers falla y la condición es 'and'")
	}
}

func TestEvaluateMatchersConditionOrAcrossMatchers(t *testing.T) {
	resp := &Response{StatusCode: 404, Body: "OK"}
	m := []Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "word", Words: []string{"OK"}},
	}
	if !EvaluateMatchers(m, "or", resp) {
		t.Error("esperaba match: al menos un matcher cumple con condición 'or'")
	}
}

func TestEvaluateMatchersEmptyDefaultsToTrue(t *testing.T) {
	resp := &Response{}
	if !EvaluateMatchers(nil, "", resp) {
		t.Error("sin matchers, la condición 'and' sobre un conjunto vacío debería ser true")
	}
}

func TestEvaluateMatchersHeaderPart(t *testing.T) {
	resp := &Response{Headers: map[string]string{"Server": "nginx/1.18.0"}}
	m := []Matcher{{Type: "word", Part: "header", Words: []string{"nginx"}}}
	if !EvaluateMatchers(m, "", resp) {
		t.Error("esperaba match sobre headers")
	}
}

func TestEvaluateMatchersUnknownTypeNoMatch(t *testing.T) {
	resp := &Response{Body: "anything"}
	m := []Matcher{{Type: "unknown"}}
	if EvaluateMatchers(m, "", resp) {
		t.Error("un tipo de matcher desconocido no debería producir match")
	}
}
