package analyzer

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/analysis"
)

const (
	AnalyzerName = "logmsglint"

	diagStartLower  = "лог-сообщение должно начинаться со строчной английской буквы"
	diagEnglishOnly = "лог-сообщение должно содержать только английский текст (кириллица и другие алфавиты запрещены)"
	diagNoSpecials  = "лог-сообщение не должно содержать спецсимволы (!, ?, ...) и эмодзи"
	diagSensitive   = "лог-сообщение содержит потенциально чувствительные данные"
)

const sensitiveReplacement = "[redacted]"

var (
	ErrInvalidConfigType      = errors.New("неверный тип конфигурации")
	ErrInvalidSensitiveRegex  = errors.New("невалидный паттерн чувствительных данных")
	ErrExpectedStringSlice    = errors.New("ожидался список строк")
	ErrExpectedStringListItem = errors.New("элемент списка не является строкой")
)

var defaultSensitivePatterns = []string{
	`(?i)\bpassword\b`,
	`(?i)\bpasswd\b`,
	`(?i)\btoken\b`,
	`(?i)\bapi[_-]?key\b`,
	`(?i)\bsecret\b`,
	`(?i)\bauthorization\b`,
	`(?i)\baccess[_-]?key\b`,
}

var slogMessageIndexes = map[string]int{
	"Debug":        0,
	"Info":         0,
	"Warn":         0,
	"Error":        0,
	"DebugContext": 1,
	"InfoContext":  1,
	"WarnContext":  1,
	"ErrorContext": 1,
	"Log":          2,
	"LogAttrs":     2,
}

var zapMessageFirstMethods = map[string]struct{}{
	"Debug":   {},
	"Info":    {},
	"Warn":    {},
	"Error":   {},
	"DPanic":  {},
	"Panic":   {},
	"Fatal":   {},
	"Debugf":  {},
	"Infof":   {},
	"Warnf":   {},
	"Errorf":  {},
	"DPanicf": {},
	"Panicf":  {},
	"Fatalf":  {},
	"Debugw":  {},
	"Infow":   {},
	"Warnw":   {},
	"Errorw":  {},
	"DPanicw": {},
	"Panicw":  {},
	"Fatalw":  {},
}

// Config описывает пользовательскую конфигурацию анализатора.
type Config struct {
	SensitivePatterns []string `json:"sensitive-patterns" yaml:"sensitive-patterns" mapstructure:"sensitive-patterns"`
}

type sensitivePattern struct {
	re *regexp.Regexp
}

// Analyzer можно использовать в unit-тестах и при прямом запуске анализатора.
var Analyzer = newDefaultAnalyzer()

// NewAnalyzer создает анализатор с учетом пользовательских паттернов чувствительных данных.
func NewAnalyzer(cfg Config) (*analysis.Analyzer, error) {
	patterns, err := compileSensitivePatterns(cfg.SensitivePatterns)
	if err != nil {
		return nil, err
	}

	analyzer := &analysis.Analyzer{
		Name: AnalyzerName,
		Doc:  "проверяет текст лог-сообщений в slog и zap",
		Run: func(pass *analysis.Pass) (any, error) {
			run(pass, patterns)
			return nil, nil
		},
	}

	return analyzer, nil
}

// ParseConfig парсит конфигурацию, которую передает golangci-lint в плагин.
func ParseConfig(raw any) (Config, error) {
	switch cfg := raw.(type) {
	case nil:
		return Config{}, nil
	case Config:
		return cfg, nil
	case *Config:
		if cfg == nil {
			return Config{}, nil
		}
		return *cfg, nil
	}

	m, ok := normalizeMap(raw)
	if !ok {
		return Config{}, fmt.Errorf("%w: ожидалась map-конфигурация, получено %T", ErrInvalidConfigType, raw)
	}

	cfg := Config{}
	for _, key := range []string{"sensitive-patterns", "sensitive_patterns", "sensitivePatterns"} {
		value, exists := m[key]
		if !exists {
			continue
		}

		patterns, err := toStringSlice(value)
		if err != nil {
			return Config{}, fmt.Errorf("ключ %q: %w", key, err)
		}
		cfg.SensitivePatterns = patterns
		break
	}

	return cfg, nil
}

// newDefaultAnalyzer гарантирует, что пакет не упадет на этапе импорта.
// Даже если дефолтная конфигурация по ошибке сломана, мы возвращаем анализатор,
// который сообщает диагностическую ошибку в рантайме.
func newDefaultAnalyzer() *analysis.Analyzer {
	a, err := NewAnalyzer(Config{})
	if err == nil {
		return a
	}

	return &analysis.Analyzer{
		Name: AnalyzerName,
		Doc:  "проверяет текст лог-сообщений в slog и zap",
		Run: func(pass *analysis.Pass) (any, error) {
			return nil, fmt.Errorf("внутренняя ошибка инициализации анализатора: %w", err)
		},
	}
}

func compileSensitivePatterns(custom []string) ([]sensitivePattern, error) {
	merged := make([]string, 0, len(defaultSensitivePatterns)+len(custom))
	merged = append(merged, defaultSensitivePatterns...)
	merged = append(merged, custom...)

	seen := make(map[string]struct{}, len(merged))
	patterns := make([]sensitivePattern, 0, len(merged))

	for _, raw := range merged {
		pattern := strings.TrimSpace(raw)
		if pattern == "" {
			continue
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", errors.Join(ErrInvalidSensitiveRegex, err), pattern)
		}
		patterns = append(patterns, sensitivePattern{re: re})
	}

	return patterns, nil
}

func run(pass *analysis.Pass, patterns []sensitivePattern) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			msgExpr, ok := extractMessageExpr(pass, call)
			if !ok {
				return true
			}

			// Важный момент: сообщение может быть не только строковым литералом,
			// но и выражением конкатенации вида "prefix" + variable.
			// Поэтому вместо попытки вычислить одно итоговое значение мы
			// извлекаем все буквальные строковые куски из AST.
			literals := extractAllStringLiterals(msgExpr)
			if len(literals) == 0 {
				return true
			}

			// Автофикс безопасен только для чистого строкового литерала.
			// Если выражение сложнее (конкатенация и т.п.), не пытаемся
			// переписывать его текстом, чтобы не сломать исходное выражение.
			canFix := canRewriteMessageExpr(msgExpr)

			for idx, literal := range literals {
				// Проверку регистра делаем только по первому строковому куску,
				// чтобы не получать ложные срабатывания на последующих частях
				// выражений конкатенации.
				if idx == 0 {
					if violated, fixed := violatesLowercaseRule(literal); violated {
						pass.Report(buildDiagnostic(msgExpr, diagStartLower, literal, fixed, canFix))
					}
				}

				if containsNonEnglishLetters(literal) {
					pass.Report(buildDiagnostic(msgExpr, diagEnglishOnly, literal, "", false))
				}

				if containsSpecialSymbolsOrEmoji(literal) {
					fixed := stripSpecialSymbolsAndEmoji(literal)
					pass.Report(buildDiagnostic(msgExpr, diagNoSpecials, literal, fixed, canFix))
				}

				if containsSensitiveData(literal, patterns) {
					fixed := redactSensitiveData(literal, patterns)
					pass.Report(buildDiagnostic(msgExpr, diagSensitive, literal, fixed, canFix))
				}
			}

			return true
		})
	}
}

// extractMessageExpr достает аргумент сообщения и опирается на type info,
// чтобы отличить реальные вызовы slog/zap от одноименных методов в другом коде.
func extractMessageExpr(pass *analysis.Pass, call *ast.CallExpr) (ast.Expr, bool) {
	fn, ok := calledFunction(pass, call)
	if !ok {
		return nil, false
	}

	pkg := fn.Pkg()
	if pkg == nil {
		return nil, false
	}

	msgIndex, ok := messageArgIndex(pkg.Path(), fn.Name())
	if !ok || msgIndex >= len(call.Args) {
		return nil, false
	}

	expr := call.Args[msgIndex]
	if !isStringExpr(pass, expr) {
		return nil, false
	}

	return expr, true
}

func calledFunction(pass *analysis.Pass, call *ast.CallExpr) (*types.Func, bool) {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if sel := pass.TypesInfo.Selections[fun]; sel != nil {
			if fn, ok := sel.Obj().(*types.Func); ok {
				return fn, true
			}
		}
		if obj := pass.TypesInfo.Uses[fun.Sel]; obj != nil {
			if fn, ok := obj.(*types.Func); ok {
				return fn, true
			}
		}
	case *ast.Ident:
		if obj := pass.TypesInfo.Uses[fun]; obj != nil {
			if fn, ok := obj.(*types.Func); ok {
				return fn, true
			}
		}
	}

	return nil, false
}

func messageArgIndex(pkgPath, fnName string) (int, bool) {
	switch pkgPath {
	case "log/slog":
		idx, ok := slogMessageIndexes[fnName]
		return idx, ok
	case "go.uber.org/zap":
		if fnName == "Log" {
			return 1, true
		}
		_, ok := zapMessageFirstMethods[fnName]
		if ok {
			return 0, true
		}
	}

	return 0, false
}

func isStringExpr(pass *analysis.Pass, expr ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[stripParens(expr)]
	if !ok || tv.Type == nil {
		return false
	}

	basic, ok := tv.Type.Underlying().(*types.Basic)
	if !ok {
		return false
	}

	return basic.Info()&types.IsString != 0
}

func canRewriteMessageExpr(expr ast.Expr) bool {
	lit, ok := stripParens(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// extractAllStringLiterals рекурсивно достает все строковые литералы из выражения.
// Мы осознанно поддерживаем только два сценария:
// 1) прямой литерал "message";
// 2) конкатенация через +, где каждая сторона может быть либо литералом,
// либо еще одной конкатенацией.
// Любые другие узлы AST (вызовы функций, идентификаторы, форматирование) игнорируем.
func extractAllStringLiterals(expr ast.Expr) []string {
	literals := make([]string, 0, 1)

	var walk func(ast.Expr)
	walk = func(node ast.Expr) {
		if node == nil {
			return
		}

		node = stripParens(node)
		switch v := node.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return
			}
			text, err := strconv.Unquote(v.Value)
			if err != nil {
				// Некорректный литерал не должен ломать анализатор.
				// Просто пропускаем узел и продолжаем обход.
				return
			}
			literals = append(literals, text)
		case *ast.BinaryExpr:
			if v.Op != token.ADD {
				return
			}
			walk(v.X)
			walk(v.Y)
		}
	}

	walk(expr)
	return literals
}

// buildDiagnostic собирает диагностику и, при необходимости, SuggestedFix.
// Важно, что SuggestedFix предлагается только для безопасного сценария, когда
// можно заменить весь исходный аргумент целиком на новый строковый литерал.
func buildDiagnostic(expr ast.Expr, message, currentText, fixedText string, allowFix bool) analysis.Diagnostic {
	diagnostic := analysis.Diagnostic{
		Pos:     expr.Pos(),
		End:     expr.End(),
		Message: message,
	}

	// Если правка не разрешена или нечего менять, возвращаем только предупреждение.
	if !allowFix || fixedText == "" || fixedText == currentText {
		return diagnostic
	}

	// Формируем правку как замену всего expression-узла на quoted-строку.
	// Такой edit корректен только для *ast.BasicLit, что гарантируется вызывающей стороной.
	diagnostic.SuggestedFixes = []analysis.SuggestedFix{
		{
			Message: "исправить сообщение логирования",
			TextEdits: []analysis.TextEdit{
				{
					Pos:     expr.Pos(),
					End:     expr.End(),
					NewText: []byte(strconv.Quote(fixedText)),
				},
			},
		},
	}

	return diagnostic
}

func violatesLowercaseRule(text string) (bool, string) {
	idx, r, size, ok := firstVisibleRune(text)
	if !ok {
		return false, ""
	}

	if r >= 'A' && r <= 'Z' {
		return true, text[:idx] + strings.ToLower(text[idx:idx+size]) + text[idx+size:]
	}

	return false, ""
}

func firstVisibleRune(text string) (int, rune, int, bool) {
	for idx, r := range text {
		if unicode.IsSpace(r) {
			continue
		}
		return idx, r, utf8.RuneLen(r), true
	}
	return 0, 0, 0, false
}

func containsNonEnglishLetters(text string) bool {
	for _, r := range text {
		if unicode.IsLetter(r) && !unicode.In(r, unicode.Latin) {
			return true
		}
	}
	return false
}

func containsSpecialSymbolsOrEmoji(text string) bool {
	if strings.Contains(text, "...") {
		return true
	}

	for _, r := range text {
		if isForbiddenPunctuation(r) || isEmojiRune(r) {
			return true
		}
	}
	return false
}

func stripSpecialSymbolsAndEmoji(text string) string {
	text = strings.ReplaceAll(text, "...", "")

	var b strings.Builder
	for _, r := range text {
		if isForbiddenPunctuation(r) || isEmojiRune(r) {
			continue
		}
		b.WriteRune(r)
	}

	return strings.Join(strings.Fields(strings.TrimSpace(b.String())), " ")
}

func isForbiddenPunctuation(r rune) bool {
	switch r {
	case '!', '?', '…':
		return true
	default:
		return false
	}
}

func isEmojiRune(r rune) bool {
	switch {
	case r >= 0x1F300 && r <= 0x1FAFF:
		return true
	case r >= 0x2600 && r <= 0x27BF:
		return true
	case r == 0xFE0F:
		return true
	default:
		return false
	}
}

func containsSensitiveData(text string, patterns []sensitivePattern) bool {
	for _, pattern := range patterns {
		if pattern.re.MatchString(text) {
			return true
		}
	}
	return false
}

func redactSensitiveData(text string, patterns []sensitivePattern) string {
	redacted := text
	for _, pattern := range patterns {
		redacted = pattern.re.ReplaceAllString(redacted, sensitiveReplacement)
	}
	return redacted
}

func stripParens(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

func normalizeMap(raw any) (map[string]any, bool) {
	switch value := raw.(type) {
	case map[string]any:
		return value, true
	case map[interface{}]interface{}:
		result := make(map[string]any, len(value))
		for k, v := range value {
			key, ok := k.(string)
			if !ok {
				continue
			}
			result[key] = v
		}
		return result, true
	default:
		return nil, false
	}
}

func toStringSlice(raw any) ([]string, error) {
	switch value := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, nil
		}
		return []string{trimmed}, nil
	case []string:
		result := make([]string, 0, len(value))
		for _, item := range value {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			result = append(result, trimmed)
		}
		return result, nil
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: %T", ErrExpectedStringListItem, item)
			}
			trimmed := strings.TrimSpace(str)
			if trimmed == "" {
				continue
			}
			result = append(result, trimmed)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("%w: получено %T", ErrExpectedStringSlice, raw)
	}
}
