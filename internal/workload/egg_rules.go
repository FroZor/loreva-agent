package workload

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

func validateEggVariableRules(egg pterodactylEgg, values map[string]string) error {
	for _, variable := range egg.Variables {
		value, err := eggVariableValue(variable, values)
		if err != nil {
			return err
		}
		if len(value) > maxEnvironmentValueBytes || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("Egg variable %s contains an oversized value or NUL", variable.Environment)
		}
		if err := validateEggVariable(variable.Environment, value, variable.Rules); err != nil {
			return err
		}
	}

	return nil
}

func eggVariableValue(variable pterodactylEggVariable, values map[string]string) (string, error) {
	if value, exists := values[variable.Environment]; exists {
		return value, nil
	}

	var value string
	if err := json.Unmarshal(variable.DefaultValue, &value); err == nil {
		return value, nil
	}

	var number json.Number
	if err := json.Unmarshal(variable.DefaultValue, &number); err == nil {
		return number.String(), nil
	}

	var boolean bool
	if err := json.Unmarshal(variable.DefaultValue, &boolean); err == nil {
		return strconv.FormatBool(boolean), nil
	}

	return "", fmt.Errorf("decode default for Egg variable %s", variable.Environment)
}

func validateEggVariable(name, value, rules string) error {
	parsed, err := splitEggRules(rules)
	if err != nil {
		return fmt.Errorf("parse rules for Egg variable %s: %w", name, err)
	}

	nullable := containsString(parsed, "nullable")
	if nullable && value == "" {
		return nil
	}
	numeric := containsString(parsed, "integer") || containsString(parsed, "numeric")

	for _, rule := range parsed {
		if err := applyEggRule(value, rule, numeric); err != nil {
			return fmt.Errorf("Egg variable %s violates %s: %w", name, rule, err)
		}
	}

	return nil
}

func applyEggRule(value, rule string, numeric bool) error {
	switch {
	case rule == "required":
		if value == "" {
			return errors.New("value is required")
		}
	case rule == "nullable", rule == "string":
		return nil
	case rule == "integer":
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return errors.New("value is not an integer")
		}
	case rule == "numeric":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return errors.New("value is not numeric")
		}
	case rule == "boolean":
		if value != "0" && value != "1" && value != "true" && value != "false" {
			return errors.New("value is not boolean")
		}
	case strings.HasPrefix(rule, "min:"):
		minimum, err := positiveRuleInteger(rule, "min:")
		if err != nil {
			return err
		}
		if numeric {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil || parsed < float64(minimum) {
				return errors.New("value is below the minimum")
			}
		} else if utf8.RuneCountInString(value) < minimum {
			return errors.New("value is shorter than the minimum")
		}
	case strings.HasPrefix(rule, "max:"):
		maximum, err := positiveRuleInteger(rule, "max:")
		if err != nil {
			return err
		}
		if numeric {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil || parsed > float64(maximum) {
				return errors.New("value exceeds the maximum")
			}
		} else if utf8.RuneCountInString(value) > maximum {
			return errors.New("value exceeds the maximum length")
		}
	case strings.HasPrefix(rule, "in:"):
		allowed := strings.Split(strings.TrimPrefix(rule, "in:"), ",")
		if !containsString(allowed, value) {
			return errors.New("value is not in the allowed set")
		}
	case strings.HasPrefix(rule, "regex:"):
		return applyEggRegex(value, strings.TrimPrefix(rule, "regex:"))
	default:
		return errors.New("unsupported Egg variable validation rule")
	}

	return nil
}

func positiveRuleInteger(rule, prefix string) (int, error) {
	value, err := strconv.Atoi(strings.TrimPrefix(rule, prefix))
	if err != nil || value < 0 || value > 1<<20 {
		return 0, errors.New("rule has an invalid numeric argument")
	}

	return value, nil
}

func applyEggRegex(value, expression string) error {
	pattern, flags, err := splitDelimitedRegex(expression)
	if err != nil {
		return err
	}
	if flags != "" {
		for _, flag := range flags {
			if !strings.ContainsRune("imsU", flag) {
				return errors.New("regex uses unsupported flags")
			}
		}
		pattern = "(?" + flags + ")" + pattern
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return errors.New("regex is not supported by the agent")
	}
	if !compiled.MatchString(value) {
		return errors.New("value does not match the required pattern")
	}

	return nil
}

func splitEggRules(value string) ([]string, error) {
	if value == "" {
		return nil, errors.New("validation rules are required")
	}

	rules := make([]string, 0, 8)
	for offset := 0; offset < len(value); {
		if strings.HasPrefix(value[offset:], "regex:") {
			end, err := regexRuleEnd(value, offset+len("regex:"))
			if err != nil {
				return nil, err
			}
			rules = append(rules, value[offset:end])
			offset = end
		} else {
			end := strings.IndexByte(value[offset:], '|')
			if end < 0 {
				end = len(value)
			} else {
				end += offset
			}
			if end == offset {
				return nil, errors.New("validation rules contain an empty item")
			}
			rules = append(rules, value[offset:end])
			offset = end
		}

		if offset < len(value) {
			if value[offset] != '|' {
				return nil, errors.New("validation rules have invalid separators")
			}
			offset++
		}
	}

	return rules, nil
}

func regexRuleEnd(value string, offset int) (int, error) {
	if offset >= len(value) || value[offset] != '/' {
		return 0, errors.New("regex rule must use slash delimiters")
	}

	escaped := false
	for index := offset + 1; index < len(value); index++ {
		character := value[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character != '/' {
			continue
		}

		index++
		for index < len(value) && value[index] != '|' {
			index++
		}

		return index, nil
	}

	return 0, errors.New("regex rule has no closing delimiter")
}

func splitDelimitedRegex(value string) (string, string, error) {
	full := "regex:" + value
	end, err := regexRuleEnd(full, len("regex:"))
	if err != nil {
		return "", "", err
	}
	closing := strings.LastIndexByte(full[:end], '/')
	if closing <= len("regex:") {
		return "", "", errors.New("regex rule has invalid delimiters")
	}

	return full[len("regex:")+1 : closing], full[closing+1 : end], nil
}
