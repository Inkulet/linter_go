package edgecases

import (
	"log/slog"

	"go.uber.org/zap"
)

func getMessage() string {
	return "dynamic message"
}

func demo() {
	logger := zap.NewNop()
	sugar := logger.Sugar()
	prefix := "auth"
	body := "payload"
	token := "abc123"
	filename := "config.yaml"

	// Проверяем raw string (многострочный литерал): чувствительный маркер token
	// должен быть найден даже внутри строкового литерала с переносом строки.
	slog.Info( /* want "лог-сообщение содержит потенциально чувствительные данные" */ "raw: " + `user token leaked
in multiline raw string`)

	// Проверяем сложную конкатенацию: в цепочке из нескольких частей есть
	// строковый литерал с token, его нужно поймать через обход BinaryExpr.
	slog.Info("user token: " + prefix + " " + body) // want "лог-сообщение содержит потенциально чувствительные данные"

	// Проверяем аналогичный кейс для zap.Logger с конкатенацией литерала и переменной.
	logger.Info("token: " + token) // want "лог-сообщение содержит потенциально чувствительные данные"

	// Проверяем форматирование SugaredLogger: восклицательный знак в шаблоне
	// должен сработать как нарушение по спецсимволам.
	sugar.Infof("failed to load %s!", filename) // want "лог-сообщение не должно содержать спецсимволы \\(!, \\?, \\.\\.\\.\\) и эмодзи"

	// Проверяем вызов с не-константным сообщением: линтер должен безопасно
	// пропустить такой случай и не падать.
	slog.Info(getMessage())
	logger.Info(getMessage())

	// Проверяем корректный сложный лог с путем и числом ретраев: срабатываний быть не должно.
	slog.Info("loaded config from /etc/config.json, retries: 3")

	// Проверяем корректный лог с UUID и путем к файлу: срабатываний быть не должно.
	logger.Info("request id 123e4567-e89b-12d3-a456-426614174000, path: /tmp/service.log")
}
