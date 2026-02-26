package analyzer

import (
	"errors"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	t.Parallel()

	a, err := NewAnalyzer(Config{SensitivePatterns: []string{`(?i)\bsession(?:[_-]|\s+)id\b`}})
	if err != nil {
		t.Fatalf("не удалось создать анализатор: %v", err)
	}

	testdata := analysistest.TestData()
	// Гоним сразу два пакета: базовый набор и набор пограничных AST-сценариев.
	analysistest.Run(t, testdata, a, "a", "edgecases")
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

func TestExtractAllStringLiterals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		expr string
		want []string
	}{
		{
			name: "один литерал",
			expr: `"simple message"`,
			want: []string{"simple message"},
		},
		{
			name: "конкатенация литерала и переменной",
			expr: `"user password: " + password`,
			want: []string{"user password: "},
		},
		{
			name: "вложенная конкатенация",
			expr: `"a" + ("b" + format())`,
			want: []string{"a", "b"},
		},
		{
			name: "без литералов",
			expr: `left + right`,
			want: []string{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := parser.ParseExprFrom(token.NewFileSet(), "", tt.expr, 0)
			if err != nil {
				t.Fatalf("не удалось распарсить выражение: %v", err)
			}

			got := extractAllStringLiterals(parsed)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("неожиданный результат: got=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestViolatesLowercaseRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		wantViolated bool
		wantFixed    string
	}{
		{
			name:         "пустая строка не считается нарушением",
			input:        "",
			wantViolated: false,
			wantFixed:    "",
		},
		{
			name:         "пробел перед строчной буквой пропускается",
			input:        "   hello",
			wantViolated: false,
			wantFixed:    "",
		},
		{
			name:         "перенос строки перед заглавной буквой фиксится",
			input:        "\nHello",
			wantViolated: true,
			wantFixed:    "\nhello",
		},
		{
			name:         "строка с цифры считается нарушением",
			input:        "1 attempt",
			wantViolated: true,
			wantFixed:    "",
		},
		{
			name:         "строка с разрешенной пунктуации считается нарушением",
			input:        ".trace started",
			wantViolated: true,
			wantFixed:    "",
		},
		{
			name:         "одна строчная буква валидна",
			input:        "a",
			wantViolated: false,
			wantFixed:    "",
		},
		{
			name:         "одна заглавная буква переводится в строчную",
			input:        "A",
			wantViolated: true,
			wantFixed:    "a",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotViolated, gotFixed := violatesLowercaseRule(tt.input)
			if gotViolated != tt.wantViolated {
				t.Fatalf("неожиданный флаг нарушения: got=%v want=%v", gotViolated, tt.wantViolated)
			}
			if gotFixed != tt.wantFixed {
				t.Fatalf("неожиданный автофикс: got=%q want=%q", gotFixed, tt.wantFixed)
			}
		})
	}
}

func TestContainsNonEnglishLetters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want bool
	}{
		{
			name: "цифры и латиница не триггерят ошибку",
			text: "status 200 retries 3",
			want: false,
		},
		{
			name: "кириллица должна детектиться",
			text: "ошибка при загрузке",
			want: true,
		},
		{
			name: "иероглифы должны детектиться",
			text: "漢字",
			want: true,
		},
		{
			name: "спецсимволы без букв не триггерят проверку языка",
			text: "...,:-_",
			want: false,
		},
		{
			name: "смешанный текст с одним русским словом должен детектиться",
			text: "user и admin",
			want: true,
		},
		{
			name: "латиница с диакритикой считается допустимой",
			text: "cafe resume déjà vu",
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := containsNonEnglishLetters(tt.text)
			if got != tt.want {
				t.Fatalf("неожиданный результат: got=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestContainsAndStripSpecialSymbolsOrEmoji(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		text         string
		wantContains bool
		wantStripped string
	}{
		{
			name:         "разрешенная пунктуация сохраняется",
			text:         "loaded config, retries: 3 - ok.",
			wantContains: false,
			wantStripped: "loaded config, retries: 3 - ok.",
		},
		{
			name:         "множественные восклицательные знаки удаляются",
			text:         "failed!!!",
			wantContains: true,
			wantStripped: "failed",
		},
		{
			name:         "вопросительный знак удаляется",
			text:         "ready?",
			wantContains: true,
			wantStripped: "ready",
		},
		{
			name:         "троеточие удаляется",
			text:         "wait...",
			wantContains: true,
			wantStripped: "wait",
		},
		{
			name:         "обычный эмодзи удаляется",
			text:         "deploy 😀 done",
			wantContains: true,
			wantStripped: "deploy done",
		},
		{
			name:         "составной эмодзи через ZWJ детектится",
			text:         "dev 👨‍💻 deployed",
			wantContains: true,
			wantStripped: "dev \u200d deployed",
		},
		{
			name:         "unicode-троеточие удаляется",
			text:         "loading…done",
			wantContains: true,
			wantStripped: "loadingdone",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotContains := containsSpecialSymbolsOrEmoji(tt.text)
			if gotContains != tt.wantContains {
				t.Fatalf("неожиданный результат contains: got=%v want=%v", gotContains, tt.wantContains)
			}

			gotStripped := stripSpecialSymbolsAndEmoji(tt.text)
			if gotStripped != tt.wantStripped {
				t.Fatalf("неожиданный результат strip: got=%q want=%q", gotStripped, tt.wantStripped)
			}
		})
	}
}

func TestContainsSensitiveData(t *testing.T) {
	t.Parallel()

	patterns, err := compileSensitivePatterns([]string{`(?i)\bsession[_-]?id\b`})
	if err != nil {
		t.Fatalf("не удалось собрать паттерны: %v", err)
	}

	tests := []struct {
		name string
		text string
		want bool
	}{
		{
			name: "API_KEY в верхнем регистре должен детектиться",
			text: "API_KEY leaked",
			want: true,
		},
		{
			name: "api-key через дефис должен детектиться",
			text: "api-key leaked",
			want: true,
		},
		{
			name: "session_id из пользовательского паттерна должен детектиться",
			text: "my session_id is 42",
			want: true,
		},
		{
			name: "session-id из пользовательского паттерна должен детектиться",
			text: "session-id=42",
			want: true,
		},
		{
			name: "обычный текст не должен детектиться",
			text: "service started successfully",
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := containsSensitiveData(tt.text, patterns)
			if got != tt.want {
				t.Fatalf("неожиданный результат contains: got=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestRedactSensitiveData(t *testing.T) {
	t.Parallel()

	patterns, err := compileSensitivePatterns([]string{`(?i)\bsession[_-]?id\b`})
	if err != nil {
		t.Fatalf("не удалось собрать паттерны: %v", err)
	}

	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "несколько чувствительных маркеров маскируются в одной строке",
			text: "password=1 token=2 API_KEY=3 session_id=4",
			want: "[redacted]=1 [redacted]=2 [redacted]=3 [redacted]=4",
		},
		{
			name: "смешанный регистр и дефисы тоже маскируются",
			text: "api-key and TOKEN and session-id",
			want: "[redacted] and [redacted] and [redacted]",
		},
		{
			name: "без чувствительных данных строка не меняется",
			text: "normal healthcheck message",
			want: "normal healthcheck message",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := redactSensitiveData(tt.text, patterns)
			if got != tt.want {
				t.Fatalf("неожиданный результат redact: got=%q want=%q", got, tt.want)
			}
		})
	}
}
