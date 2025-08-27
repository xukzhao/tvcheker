package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// NewLogger 创建一个新的日志记录器
func NewLogger(level LogLevel, output io.Writer) *Logger {
	if output == nil {
		output = os.Stdout
	}
	return &Logger{
		level:  level,
		output: output,
	}
}

// log 记录日志的内部方法
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if l.level >= level {
		l.mutex.Lock()
		defer l.mutex.Unlock()

		message := format
		if len(args) > 0 {
			message = fmt.Sprintf(format, args...)
		}

		// 检查是否为进度更新（以\r结尾）
		isProgress := strings.HasSuffix(format, "\r")

		if isProgress {
			// 对于进度更新，覆盖当前行并确保正确显示
			fmt.Fprintf(l.output, "\r%s [INFO] %s\033[K", time.Now().Format("2006-01-02 15:04:05"), message)
		} else {
			// 对于普通日志，添加时间戳并换行
			fmt.Fprintf(l.output, "%s [INFO] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
		}
	}
}

// Info 记录INFO级别的日志
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LogLevelNormal, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level >= LogLevelNormal {
		l.log(LogLevelNormal, format, args...)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	// 错误总是输出，不管日志级别
	l.log(LogLevelNormal, format, args...)
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.level >= LogLevelVerbose {
		l.log(LogLevelVerbose, format, args...)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level >= LogLevelDebug {
		l.log(LogLevelDebug, format, args...)
	}
}

func (l *Logger) Trace(format string, args ...interface{}) {
	if l.level >= LogLevelTrace {
		l.log(LogLevelTrace, format, args...)
	}
}

// SetLevel 设置日志级别
func (l *Logger) SetLevel(level LogLevel) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.level = level
}

// GetLevel 获取当前日志级别
func (l *Logger) GetLevel() LogLevel {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.level
}
