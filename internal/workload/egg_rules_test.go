package workload

import "testing"

func TestEggVariableRulesRejectUnsafeJarPath(t *testing.T) {
	rules := `required|regex:/^([\w\d._-]+)(\.jar)$/`

	if err := validateEggVariable("SERVER_JARFILE", "server.jar", rules); err != nil {
		t.Fatalf("valid server jar was rejected: %v", err)
	}
	if err := validateEggVariable("SERVER_JARFILE", "../../server.jar", rules); err == nil {
		t.Fatal("unsafe server jar path was accepted")
	}
}

func TestEggVariableRulesPreservePipeInsideRegex(t *testing.T) {
	rules, err := splitEggRules(`required|regex:/^(paper|purpur)$/|max:16`)
	if err != nil {
		t.Fatalf("parse Egg rules: %v", err)
	}
	if len(rules) != 3 || rules[1] != `regex:/^(paper|purpur)$/` {
		t.Fatalf("unexpected parsed rules: %#v", rules)
	}
	if err := validateEggVariable("SERVER_TYPE", "paper", `required|regex:/^(paper|purpur)$/`); err != nil {
		t.Fatalf("valid regex alternative was rejected: %v", err)
	}
}

func TestEggVariableRulesRejectUnknownRule(t *testing.T) {
	if err := validateEggVariable("VALUE", "x", "required_if:OTHER,true"); err == nil {
		t.Fatal("unsupported Egg rule was ignored")
	}
}
