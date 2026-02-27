# linter_go

Кастомный линтер для Go, который проверяет текст лог-сообщений в вызовах `log/slog` и `go.uber.org/zap`.

## Что проверяет

1. Сообщение начинается со строчной английской буквы.
2. В сообщении нет кириллицы и других не-латинских букв.
3. В сообщении нет спецсимволов `!`, `?`, `...` и эмодзи.
4. В сообщении нет потенциально чувствительных данных (`password`, `token`, `api_key` и др.).

Линтер построен на `golang.org/x/tools/go/analysis`, поддерживает `SuggestedFixes` и кастомные паттерны чувствительных данных.

## Требования

1. Go `1.22+` (рекомендуется версия из `go.mod`).
2. `golangci-lint` (локально установленный бинарник).
3. Linux/macOS (сборка `.so` плагина через `-buildmode=plugin`).

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

## Быстрый старт

```bash
git clone <https://github.com/Inkulet/linter_go>
cd linter_go
go mod tidy
mkdir -p build
go build -buildmode=plugin -o build/logmsglint.so ./plugin
```

После этого добавьте конфиг `golangci-lint` (пример ниже) и запустите:

```bash
golangci-lint run
```

## Сборка плагина для golangci-lint

```bash
mkdir -p build
go build -buildmode=plugin -o build/logmsglint.so ./plugin
```

## Конфигурация golangci-lint

Создайте файл `.golangci.yml` в проекте, где хотите запускать линтер:

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

Если запускаете `golangci-lint` не из корня репозитория с плагином, укажите абсолютный путь в `path`.

## Локальная проверка линтера

```bash
go test ./...
golangci-lint run
```

## Локальный запуск тестов

```bash
go test ./...
```

## Частые проблемы

1. `plugin.Open(...): no such file or directory`
   Причина: неверный `path` в `.golangci.yml`.
   Решение: проверьте путь до `build/logmsglint.so` (лучше использовать абсолютный путь).

2. `plugin was built with a different version of package ...`
   Причина: плагин собран другой версией Go, чем та, которой запускается `golangci-lint`.
   Решение: пересоберите плагин той же версией Go, которой запускаете линтер.

3. `unknown linter: logmsglint`
   Причина: кастомный линтер не включен или не прочитан конфиг.
   Решение: проверьте блок `linters-settings.custom.logmsglint` и `linters.enable`.
