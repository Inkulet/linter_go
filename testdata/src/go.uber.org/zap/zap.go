package zap

type Logger struct{}
type SugaredLogger struct{}
type Field struct{}

type Level int8

func NewNop() *Logger { return &Logger{} }

func (l *Logger) Sugar() *SugaredLogger { return &SugaredLogger{} }

func (l *Logger) Info(string, ...Field) {}
func (l *Logger) Warn(string, ...Field) {}

func (s *SugaredLogger) Infof(string, ...any) {}
func (s *SugaredLogger) Infow(string, ...any) {}
