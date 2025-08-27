package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// 日志和配置需要先于上下文创建
	logger := NewLogger(LogLevelNormal, os.Stdout)
	configManager := NewConfigManager(logger)

	config, err := configManager.LoadConfig()
	if err != nil {
		fmt.Printf("加载配置失败: %v\n", err)
		os.Exit(1)
	}

	// 从配置更新日志级别
	logger.level = parseLogLevel(config.LogLevel)

	// 使用配置的全局超时创建主上下文
	timeoutDuration := time.Duration(config.GlobalTimeout) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	// 设置优雅关闭
	setupGracefulShutdown(cancel)

	// 运行主程序并处理错误
	if err := run(ctx, config, logger); err != nil {
		fmt.Printf("程序执行失败: %v\n", err)
		os.Exit(1)
	}
}

// setupGracefulShutdown 设置优雅关闭处理
func setupGracefulShutdown(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\n收到中断信号，正在优雅关闭...")
		cancel()
	}()
}

// findAndLoadGroupConfig 尝试从主路径或备选路径列表加载分组配置。
// 如果所有尝试都失败，则返回默认配置。
func findAndLoadGroupConfig(initialPath string, logger *Logger) *GroupConfig {
	var groupConfig *GroupConfig
	var err error

	// 首先尝试初始路径
	if initialPath != "" {
		groupConfig, err = loadGroupConfig(initialPath)
		if err == nil {
			return groupConfig
		}
	}

	// 如果初始路径失败或为空，则尝试备选路径
	candidates := []string{"groups.json", "go/groups.json", "web/groups.json"}
	for _, p := range candidates {
		if _, statErr := os.Stat(p); statErr == nil {
			groupConfig, err = loadGroupConfig(p)
			if err == nil {
				logger.Info("在 %s 找到并加载了分组配置\n", p)
				return groupConfig
			}
		}
	}

	// 如果所有尝试都失败，则使用默认值
	logger.Warn("无法加载任何分组配置文件，将使用默认分组\n")
	return getDefaultGroupConfig()
}

// run 是主程序逻辑函数，返回错误而不是直接终止程序
func run(ctx context.Context, config *Config, logger *Logger) error {
	// 加载分组配置
	groupConfig := findAndLoadGroupConfig(config.GroupsFile, logger)

	// 从文件和URL读取频道
	localChannels, networkChannels, err := readAllChannels(config.FilePath, config.URLs, config.URLFile, logger)
	if err != nil {
		return fmt.Errorf("读取频道时出错: %w", err)
	}

	// 去除重复项
	localChannels = removeDuplicates(localChannels)
	networkChannels = removeDuplicates(networkChannels)

	channels := append(localChannels, networkChannels...)

	logger.Info("已加载 %d 个本地频道和 %d 个网络频道（去重后共 %d 个）\n", len(localChannels), len(networkChannels), len(channels))
	logger.Info("使用 %d 个并发工作线程和 %d 秒超时时间进行检查\n", config.Concurrency, config.Timeout)

	// 更新系统监控信息
	sysMonitor.Update()
	actualConcurrency := sysMonitor.GetRecommendedConcurrency(config.Concurrency)
	if actualConcurrency != config.Concurrency {
		logger.Info("根据系统负载调整并发数从 %d 到 %d\n", config.Concurrency, actualConcurrency)
		config.Concurrency = actualConcurrency
	}

	// 创建工作线程管理器
	workerManager := NewWorkerManager(ctx, config, logger)

	// 处理频道
	allResults, err := workerManager.ProcessChannels(channels)
	if err != nil {
		return fmt.Errorf("处理频道时出错: %w", err)
	}

	outputFile, err := os.Create(config.Output)
	if err != nil {
		return fmt.Errorf("创建输出文件时出错: %w", err)
	}
	defer outputFile.Close()

	outputWriter := bufio.NewWriter(outputFile)
	defer outputWriter.Flush()

	var multiWriter io.Writer
	if parseLogLevel(config.LogLevel) >= LogLevelNormal {
		multiWriter = io.MultiWriter(os.Stdout, outputWriter)
	} else {
		multiWriter = outputWriter
	}

	// 处理结果
	availableChannels, stats, err := processResultsList(ctx, allResults, multiWriter, parseLogLevel(config.LogLevel))
	if err != nil {
		return fmt.Errorf("处理结果时出错: %w", err)
	}

	logLevel := parseLogLevel(config.LogLevel)
	if logLevel >= LogLevelNormal {
		displayStats(stats, multiWriter)
		fmt.Printf("\n结果已保存到 %s\n", config.Output)
	}

	if err := saveAvailableChannels(availableChannels, groupConfig, logLevel, config.OutputDir); err != nil {
		logger.Warn("保存可用频道时出错: %v\n", err)
	} else {
		logger.Info("可用频道已保存到 %s/live.txt 和 %s/live.m3u\n", config.OutputDir, config.OutputDir)
	}

	return nil
}
