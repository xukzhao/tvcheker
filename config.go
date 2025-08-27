package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// ConfigManager 配置管理器，负责处理所有配置相关操作
type ConfigManager struct {
	Logger *Logger
}

// NewConfigManager 创建一个新的配置管理器
func NewConfigManager(logger *Logger) *ConfigManager {
	return &ConfigManager{
		Logger: logger,
	}
}

// LoadConfig 加载配置，包括命令行参数和配置文件
func (cm *ConfigManager) LoadConfig() (*Config, error) {
	// 解析命令行参数
	config, err := parseFlags()
	if err != nil {
		return nil, fmt.Errorf("解析命令行参数失败 %w", err)
	}

	// 尝试从配置文件加载配置
	configPaths := []string{"config.json", "go/config.json", "web/config.json"}
	for _, cfgPath := range configPaths {
		if _, statErr := os.Stat(cfgPath); statErr == nil {
			fileConfig, loadErr := loadConfigFromFile(cfgPath)
			if loadErr != nil {
				if cm.Logger != nil {
					cm.Logger.Warn("配置文件 %s 存在但格式错误 %v", cfgPath, loadErr)
				}
			} else {
				mergeConfig(config, fileConfig)
				if cm.Logger != nil {
					cm.Logger.Info("已加载配置文件 %s", cfgPath)
				}
				break
			}
		}
	}

	// 验证配置
	if validateErr := validateConfig(config); validateErr != nil {
		return nil, fmt.Errorf("配置验证失败 %w", validateErr)
	}

	return config, nil
}

// validateConfig 验证配置参数
func validateConfig(config *Config) error {
	if config.Concurrency <= 0 || config.Concurrency > 100 {
		return fmt.Errorf("并发数应在1-100之间，当前值 %d", config.Concurrency)
	}
	if config.Timeout <= 0 || config.Timeout > 300 {
		return fmt.Errorf("超时时间应在1-300秒之间，当前值 %d", config.Timeout)
	}
	if config.MaxRetries < 0 || config.MaxRetries > 10 {
		return fmt.Errorf("最大重试次数应在0-10之间，当前值 %d", config.MaxRetries)
	}
	mode := strings.ToLower(config.FFprobeMode)
	if mode != "auto" && mode != "disable" && mode != "only" && mode != "" {
		return fmt.Errorf("无效的ffprobe模式: %s。允许的值为 auto, disable, only", config.FFprobeMode)
	}
	if config.GlobalTimeout <= 0 {
		return fmt.Errorf("全局超时时间必须大于0，当前值 %d", config.GlobalTimeout)
	}
	return nil
}

// parseFlags 解析命令行参数
func parseFlags() (*Config, error) {
	filePath := flag.String("file", "tv.txt", "本地电视频道文件路径")
	urls := flag.String("urls", "", "获取电视频道的URL列表，用逗号分隔")
	urlFile := flag.String("urlfile", "", "包含URL的文件路径，每行一个URL")
	groupsFile := flag.String("groups", "groups.json", "自定义分组配置文件路径")
	concurrency := flag.Int("concurrency", 10, "并发检查数")
	timeout := flag.Int("timeout", 30, "每个请求的超时时间（秒）")
	output := flag.String("output", "out.txt", "结果输出文件")
	maxRetries := flag.Int("retries", 2, "最大重试次数")
	logLevel := flag.String("loglevel", "normal", "日志级别: silent, normal, verbose")
	outputDir := flag.String("outdir", "public", "可用频道输出目录 (txt/m3u)")
	secureConnect := flag.Bool("secure", false, "是否使用安全连接（验证SSL证书）。默认为false，如果设置为true，将验证SSL证书，提高安全性但可能导致某些站点无法访问")
	ffprobeMode := flag.String("ffprobe-mode", "auto", "FFprobe检测模式: auto, disable, only")
	globalTimeout := flag.Int("global-timeout", 30, "程序运行的总超时时间（分钟）")
	flag.Parse()
	return &Config{
		FilePath:      *filePath,
		URLs:          *urls,
		URLFile:       *urlFile,
		GroupsFile:    *groupsFile,
		Concurrency:   *concurrency,
		Timeout:       *timeout,
		Output:        *output,
		MaxRetries:    *maxRetries,
		LogLevel:      *logLevel,
		OutputDir:     *outputDir,
		SecureConnect: *secureConnect,
		FFprobeMode:   *ffprobeMode,
		GlobalTimeout: *globalTimeout,
	}, nil
}

// loadConfigFromFile 从文件加载配置
func loadConfigFromFile(path string) (*FileConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var config FileConfig
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// mergeConfig 合并命令行配置和文件配置
func mergeConfig(config *Config, fileConfig *FileConfig) {
	if fileConfig.FilePath != "" {
		config.FilePath = fileConfig.FilePath
	}
	if len(fileConfig.URLs) > 0 {
		config.URLs = strings.Join(fileConfig.URLs, ",")
	}
	if fileConfig.URLFile != "" {
		config.URLFile = fileConfig.URLFile
	}
	if fileConfig.GroupsFile != "" {
		config.GroupsFile = fileConfig.GroupsFile
	}
	if fileConfig.Concurrency > 0 {
		config.Concurrency = fileConfig.Concurrency
	}
	if fileConfig.Timeout > 0 {
		config.Timeout = fileConfig.Timeout
	}
	if fileConfig.Output != "" {
		config.Output = fileConfig.Output
	}
	if fileConfig.MaxRetries > 0 {
		config.MaxRetries = fileConfig.MaxRetries
	}
	if fileConfig.LogLevel != "" {
		config.LogLevel = fileConfig.LogLevel
	}
	if fileConfig.OutputDir != "" {
		config.OutputDir = fileConfig.OutputDir
	}
	if fileConfig.FFprobeMode != "" {
		config.FFprobeMode = fileConfig.FFprobeMode
	}
	if fileConfig.GlobalTimeout > 0 {
		config.GlobalTimeout = fileConfig.GlobalTimeout
	}
	config.SecureConnect = fileConfig.SecureConnect
}

// parseLogLevel 解析日志级别
func parseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "silent":
		return LogLevelSilent
	case "verbose":
		return LogLevelVerbose
	default:
		return LogLevelNormal
	}
}
