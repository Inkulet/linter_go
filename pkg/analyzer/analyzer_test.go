package analyzer

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	t.Parallel()

	a, err := NewAnalyzer(Config{SensitivePatterns: []string{`(?i)\bsession\s+id\b`}})
	if err != nil {
		t.Fatalf("не удалось создать анализатор: %v", err)
	}

	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, a, "a")
}

func TestParseConfig(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig(map[string]any{
		"sensitive-patterns": []any{"(?i)session[_-]?id", "(?i)client_secret"},
	})
	if err != nil {
		t.Fatalf("не удалось распарсить конфигурацию: %v", err)
	}

	expected := []string{"(?i)session[_-]?id", "(?i)client_secret"}
	if !reflect.DeepEqual(cfg.SensitivePatterns, expected) {
		t.Fatalf("неожиданный список паттернов: got=%v want=%v", cfg.SensitivePatterns, expected)
	}
}

func TestNewAnalyzer_InvalidSensitivePattern(t *testing.T) {
	t.Parallel()

	_, err := NewAnalyzer(Config{SensitivePatterns: []string{"("}})
	if err == nil {
		t.Fatal("ожидалась ошибка для невалидного regex-паттерна")
	}

	if !errors.Is(err, ErrInvalidSensitiveRegex) {
		t.Fatalf("ожидалась ошибка ErrInvalidSensitiveRegex, получено: %v", err)
	}
}

func TestParseConfig_InvalidType(t *testing.T) {
	t.Parallel()

	_, err := ParseConfig("invalid")
	if err == nil {
		t.Fatal("ожидалась ошибка для невалидного типа конфигурации")
	}

	if !errors.Is(err, ErrInvalidConfigType) {
		t.Fatalf("ожидалась ошибка ErrInvalidConfigType, получено: %v", err)
	}
}

func TestParseConfig_InvalidPatternItemType(t *testing.T) {
	t.Parallel()

	_, err := ParseConfig(map[string]any{
		"sensitive-patterns": []any{"ok", 42},
	})
	if err == nil {
		t.Fatal("ожидалась ошибка для невалидного типа элемента в паттернах")
	}

	if !errors.Is(err, ErrExpectedStringListItem) {
		t.Fatalf("ожидалась ошибка ErrExpectedStringListItem, получено: %v", err)
	}
}
