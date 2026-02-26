# inter_go

Кастомный линтер для Go, который проверяет текст лог-сообщений в вызовах `log/slog` и `go.uber.org/zap`.

## Что проверяет

1. Сообщение начинается со строчной английской буквы.
2. В сообщении нет кириллицы и других не-латинских букв.
3. В сообщении нет спецсимволов `!`, `?`, `...` и эмодзи.
4. В сообщении нет потенциально чувствительных данных (`password`, `token`, `api_key` и др.).

Линтер построен на `golang.org/x/tools/go/analysis`, поддерживает `SuggestedFixes` и кастомные паттерны чувствительных данных.

## Структура проекта

```text
.
├── .github/workflows/linter.yml
├── .gitignore
├── go.mod
├── pkg/analyzer/analyzer.go
├── pkg/analyzer/analyzer_test.go
├── pkg/analyzer/testdata/src/a/main.go
├── pkg/analyzer/testdata/src/go.uber.org/zap/zap.go
├── plugin/main.go
└── README.md
```

## Сборка плагина для golangci-lint

```bash
mkdir -p build
go build -buildmode=plugin -o build/logmsglint.so ./plugin
```

## Пример конфигурации golangci-lint

```yaml
linters-settings:
  custom:
    logmsglint:
      path: ./build/logmsglint.so
      description: Checks slog/zap log messages
      original-url: github.com/glebpashkov/linter_go
      settings:
        sensitive-patterns:
          - '(?i)\\bsession[_-]?id\\b'
          - '(?i)\\bclient_secret\\b'

linters:
  enable:
    - logmsglint
```

## Локальный запуск тестов

```bash
go test ./...
```
