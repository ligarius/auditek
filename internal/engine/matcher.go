package engine

import (
	"regexp"
	"strconv"
	"strings"
)

func EvaluateMatchers(matchers []Matcher, condition string, resp *Response) bool {
	if condition == "" {
		condition = "and"
	}

	results := make([]bool, len(matchers))
	for i, m := range matchers {
		results[i] = evaluateOne(m, resp)
	}

	if condition == "or" {
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}

	for _, r := range results {
		if !r {
			return false
		}
	}
	return true
}

func evaluateOne(m Matcher, resp *Response) bool {
	result := evaluateRaw(m, resp)
	if m.Negative {
		return !result
	}
	return result
}

func evaluateRaw(m Matcher, resp *Response) bool {
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if resp.StatusCode == s {
				return true
			}
		}
		return false

	case "word":
		target := getPart(m.Part, resp)
		return matchWords(target, m.Words, m.Condition)

	case "regex":
		target := getPart(m.Part, resp)
		return matchRegex(target, m.Regex, m.Condition)

	case "size":
		target := getPart(m.Part, resp)
		if len(m.Words) == 0 {
			return false
		}
		expectedSize, _ := strconv.Atoi(m.Words[0])
		return len(target) == expectedSize

	default:
		return false
	}
}

func getPart(part string, resp *Response) string {
	switch part {
	case "header":
		var sb strings.Builder
		for k, v := range resp.Headers {
			sb.WriteString(k + ": " + v + "\n")
		}
		return sb.String()
	case "body", "":
		return resp.Body
	default:
		return resp.Body
	}
}

func matchWords(target string, words []string, condition string) bool {
	if condition == "" {
		condition = "or"
	}
	matched := 0
	for _, w := range words {
		if strings.Contains(target, w) {
			matched++
		}
	}
	if condition == "and" {
		return matched == len(words)
	}
	return matched > 0
}

func matchRegex(target string, patterns []string, condition string) bool {
	if condition == "" {
		condition = "or"
	}
	matched := 0
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(target) {
			matched++
		}
	}
	if condition == "and" {
		return matched == len(patterns)
	}
	return matched > 0
}
