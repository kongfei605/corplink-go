package main

import (
	"encoding/json"
	"regexp"
	"strings"
)

type Template struct {
	src     string
	matches [][2]int
}

func NewTemplate(template string) *Template {
	regex := regexp.MustCompile(`\{\{([^}]*)\}\}`)
	matches := regex.FindAllStringIndex(template, -1)

	// Convert [][]int to [][2]int
	matchPairs := make([][2]int, len(matches))
	for i, match := range matches {
		matchPairs[i] = [2]int{match[0], match[1]}
	}

	return &Template{
		src:     template,
		matches: matchPairs,
	}
}

func (t *Template) Render(vals interface{}) string {
	return t.RenderNamed(vals)
}

func (t *Template) RenderNamed(vals interface{}) string {
	if len(t.matches) == 0 {
		return t.src
	}

	// Convert vals to map using json as intermediate
	jsonData, _ := json.Marshal(vals)
	var valMap map[string]interface{}
	json.Unmarshal(jsonData, &valMap)

	var parts []string
	templateStr := t.src

	// Copy from template start to first arg
	first := t.matches[0][0]
	if first > 0 {
		parts = append(parts, templateStr[0:first])
	}

	var prevEnd int
	for _, match := range t.matches {
		start, end := match[0], match[1]

		// Copy from previous argument end till current argument start
		if prevEnd > 0 {
			parts = append(parts, templateStr[prevEnd:start])
		}

		// Get argument name without braces
		arg := templateStr[start:end]
		argName := arg[2 : len(arg)-2]

		if val, ok := valMap[argName]; ok {
			switch v := val.(type) {
			case string:
				parts = append(parts, v)
			default:
				jsonStr, _ := json.Marshal(v)
				parts = append(parts, string(jsonStr))
			}
		} else {
			parts = append(parts, arg)
		}

		prevEnd = end
	}

	// Copy remainder of template after last argument
	if prevEnd < len(templateStr) {
		parts = append(parts, templateStr[prevEnd:])
	}

	return strings.Join(parts, "")
}
