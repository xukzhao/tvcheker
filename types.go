package main

import (
	"io"
	"regexp"
	"sync"
	"time"
)

// Channel 代表一个电视频道，包含名称和URL
type Channel struct {
	Name   string
	URL    string
	Source string // 新增字段，标记来源（local或network）
}

// Result 代表检查频道的结果
type Result struct {
	Channel      Channel
	Available    bool
	ResponseTime time.Duration
	Error        error
}

// GroupConfig 定义分组配置结构
type GroupConfig struct {
	Groups        map[string][]string `json:"groups"`
	RegexGroups   map[string]string   `json:"regex_groups"`
	CompiledRegex map[string]*regexp.Regexp
	GroupOrder    []string `json:"group_order"`
}

// Config 代表程序配置
type Config struct {
	FilePath      string
	URLs          string
	URLFile       string
	GroupsFile    string
	Concurrency   int
	Timeout       int
	Output        string
	MaxRetries    int
	LogLevel      string
	OutputDir     string
	SecureConnect bool
	FFprobeMode   string // 新增FFprobe检测模式: auto, disable, only
	GlobalTimeout int    // 新增全局超时（分钟）
}

// Stats 代表统计信息
type Stats struct {
	LocalAvailable     int
	LocalUnavailable   int
	NetworkAvailable   int
	NetworkUnavailable int
}

// Progress 代表进度信息
type Progress struct {
	Processed int
	Total     int
	Available int
	logLevel  LogLevel
	mutex     sync.Mutex
}

// FileConfig 代表文件配置结构
type FileConfig struct {
	FilePath      string   `json:"file_path,omitempty"`
	URLs          []string `json:"urls,omitempty"`
	URLFile       string   `json:"url_file,omitempty"`
	GroupsFile    string   `json:"groups_file,omitempty"`
	Concurrency   int      `json:"concurrency,omitempty"`
	Timeout       int      `json:"timeout,omitempty"`
	Output        string   `json:"output,omitempty"`
	MaxRetries    int      `json:"max_retries,omitempty"`
	LogLevel      string   `json:"log_level,omitempty"`
	OutputDir     string   `json:"output_dir,omitempty"`
	SecureConnect bool     `json:"secure_connect"`
	FFprobeMode   string   `json:"ffprobe_mode,omitempty"`
	GlobalTimeout int      `json:"global_timeout,omitempty"` // 新增全局超时（分钟）
}

// LogLevel 定义日志级别类型
type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelNormal
	LogLevelVerbose
	LogLevelDebug
	LogLevelTrace
)

// Logger 统一日志处理结构
type Logger struct {
	level  LogLevel
	mutex  sync.Mutex
	output io.Writer
}

// ChannelError 已移动到 errors.go 文件中

// SystemMonitor 系统资源监控结构
type SystemMonitor struct {
	mutex          sync.Mutex
	lastUpdate     time.Time
	cpuUsage       float64     // CPU使用率
	memUsage       float64     // 内存使用率
	goroutineCount int         // Goroutine数量
	networkIO      interface{} // 网络IO信息占位符
}
