package log

import (
	"github.com/taliesins/traefik-plugin-oidc/log/encoder"
	"github.com/taliesins/traefik-plugin-oidc/log/level"
	"github.com/taliesins/traefik-plugin-oidc/log/syncer"
	"os"
)

func NewLogger() (logger *Logger, err error) {
	config := encoder.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    encoder.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     encoder.DefaultLineEnding,
		EncodeLevel:    encoder.LowercaseLevelEncoder,
		EncodeTime:     encoder.ISO8601TimeEncoder,
		EncodeDuration: encoder.SecondsDurationEncoder,
		EncodeCaller:   encoder.ShortCallerEncoder,
	}

	consoleEncoder := encoder.NewConsoleEncoder(config)

	levelToLog := level.LevelEnablerFunc(func(lvl level.Level) bool {
		return lvl >= level.DebugLevel
	})

	stackTraceAppendLevelToLog := level.LevelEnablerFunc(func(lvl level.Level) bool {
		return lvl >= level.ErrorLevel
	})

	core := encoder.NewCore(consoleEncoder, syncer.Lock(os.Stdout), levelToLog)

	logger = New(core, AddCaller(), AddStacktrace(stackTraceAppendLevelToLog))

	return logger, nil
}
