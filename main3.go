package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
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
	RegexGroups   map[string]string   `json:"regex_groups"` // 新增正则表达式分组
	CompiledRegex map[string]*regexp.Regexp
	GroupOrder    []string `json:"group_order"`
}

// Config 代表程序配置
type Config struct {
	FilePath    string
	URLs        string
	URLFile     string
	GroupsFile  string
	Concurrency int
	Timeout     int
	Output      string
	MaxRetries  int
	LogLevel    string
	OutputDir   string
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
	logLevel  LogLevel // 新增字段，控制日志输出
	mutex     sync.Mutex
}

// FileConfig 代表文件配置结构
type FileConfig struct {
	FilePath    string   `json:"file_path"`
	URLs        []string `json:"urls"`
	URLFile     string   `json:"url_file"`
	GroupsFile  string   `json:"groups_file"`
	Concurrency int      `json:"concurrency"`
	Timeout     int      `json:"timeout"`
	Output      string   `json:"output"`
	MaxRetries  int      `json:"max_retries"`
	LogLevel    string   `json:"log_level"`
	OutputDir   string   `json:"output_dir"`
}

// LogLevel 定义日志级别类型
type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelNormal
	LogLevelVerbose
)

// Logger 统一日志处理结构
type Logger struct {
	level LogLevel
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.level >= LogLevelNormal {
		fmt.Printf(format+"\n", args...)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level >= LogLevelNormal {
		fmt.Printf("警告: "+format+"\n", args...)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	fmt.Printf("错误: "+format+"\n", args...)
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.level >= LogLevelVerbose {
		fmt.Printf(format+"\n", args...)
	}
}

func main() {
	// 设置全局超时（例如30分钟）
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// 设置优雅关闭
	setupGracefulShutdown(cancel)

	// 运行主程序并处理错误
	if err := run(ctx); err != nil {
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
		// 不直接 os.Exit，让主流程自然退出
	}()
}

// run 是主程序逻辑函数，返回错误而不是直接终止程序
func run(ctx context.Context) error {
	// 解析命令行参数
	config, err := parseFlags()
	if err != nil {
		return fmt.Errorf("解析命令行参数失败: %w", err)
	}

	// 验证配置
	if err := validateConfig(config); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}

	// 创建日志记录器
	logger := &Logger{level: parseLogLevel(config.LogLevel)}

	// 尝试从配置文件加载配置
	// 尝试多路径加载配置文件
configPaths := []string{"config.json", "go/config.json", "web/config.json"}
for _, cfgPath := range configPaths {
	if _, err := os.Stat(cfgPath); err == nil {
		fileConfig, err := loadConfigFromFile(cfgPath)
		if err != nil {
			logger.Warn("配置文件 %s 存在但格式错误: %v", cfgPath, err)
		} else {
			mergeConfig(config, fileConfig)
			logger.Info("已加载配置文件 %s", cfgPath)
			break
		}
	}
}

	// 读取分组配置
	// 支持多路径回退查找 groups.json
var groupConfig *GroupConfig
var groupErr error
if config.GroupsFile != "" {
	groupConfig, groupErr = loadGroupConfig(config.GroupsFile)
}
if groupErr != nil || groupConfig == nil {
	candidates := []string{"groups.json", "go/groups.json", "web/groups.json"}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			groupConfig, groupErr = loadGroupConfig(p)
			if groupErr == nil { break }
		}
	}
}
if groupErr != nil || groupConfig == nil {
	logger.Warn("无法加载分组配置文件，使用默认分组")
	groupConfig = getDefaultGroupConfig()
}

	// 从文件和URL读取频道
	localChannels, networkChannels, err := readAllChannels(config.FilePath, config.URLs, config.URLFile, logger)
	if err != nil {
		return fmt.Errorf("读取频道时出错: %w", err)
	}

	// 去除重复项
	localChannels = removeDuplicates(localChannels)
	networkChannels = removeDuplicates(networkChannels)

	// 合并频道，本地频道优先
	channels := append(localChannels, networkChannels...)

	logger.Info("已加载 %d 个本地频道和 %d 个网络频道（去重后共 %d 个）", len(localChannels), len(networkChannels), len(channels))
	logger.Info("使用 %d 个并发工作线程和 %d 秒超时时间进行检查", config.Concurrency, config.Timeout)

	// 创建处理通道
	jobs := make(chan Channel, len(channels))
	results := make(chan Result, len(channels))

	// 创建进度显示
	progress := &Progress{Total: len(channels), logLevel: parseLogLevel(config.LogLevel)}

	// 启动工作线程
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, time.Duration(config.Timeout)*time.Second, config.MaxRetries, progress)
	}

	// 发送任务
	for _, channel := range channels {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			close(jobs)
			return fmt.Errorf("操作被取消: %w", ctx.Err())
		default:
			jobs <- channel
		}
	}
	close(jobs)

	// 关闭结果通道在所有goroutine完成后
	go func() {
		wg.Wait()
		close(results)
	}()

	// 创建输出文件
	outputFile, err := os.Create(config.Output)
	if err != nil {
		return fmt.Errorf("创建输出文件时出错: %w", err)
	}
	defer outputFile.Close()

	// 使用MultiWriter同时写入到控制台和文件
	outputWriter := bufio.NewWriter(outputFile)
	defer outputWriter.Flush()

	// 创建一个MultiWriter，可以同时写入到多个位置
	var multiWriter io.Writer
	if parseLogLevel(config.LogLevel) >= LogLevelNormal {
		multiWriter = io.MultiWriter(os.Stdout, outputWriter)
	} else {
		multiWriter = outputWriter
	}

	// 处理结果
	availableChannels, stats, err := processResults(ctx, results, multiWriter, progress, parseLogLevel(config.LogLevel))
	if err != nil {
		return fmt.Errorf("处理结果时出错: %w", err)
	}

	// 显示统计信息
	logLevel := parseLogLevel(config.LogLevel)
	if logLevel >= LogLevelNormal {
		displayStats(stats, multiWriter)
		fmt.Printf("\n结果已保存到 %s\n", config.Output)
	}

	// 将可用频道保存到指定输出目录
	if err := saveAvailableChannels(availableChannels, groupConfig, logLevel, config.OutputDir); err != nil {
		logger.Warn("保存可用频道时出错: %v", err)
	} else {
		logger.Info("可用频道已保存到 %s/live.txt 和 %s/live.m3u", config.OutputDir, config.OutputDir)
	}

	return nil
}

// validateConfig 验证配置参数
func validateConfig(config *Config) error {
	if config.Concurrency <= 0 || config.Concurrency > 100 {
		return fmt.Errorf("并发数应在1-100之间，当前值: %d", config.Concurrency)
	}

	if config.Timeout <= 0 || config.Timeout > 300 {
		return fmt.Errorf("超时时间应在1-300秒之间，当前值: %d", config.Timeout)
	}

	if config.MaxRetries < 0 || config.MaxRetries > 10 {
		return fmt.Errorf("最大重试次数应在0-10之间，当前值: %d", config.MaxRetries)
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
	flag.Parse()

	return &Config{
		FilePath:    *filePath,
		URLs:        *urls,
		URLFile:     *urlFile,
		GroupsFile:  *groupsFile,
		Concurrency: *concurrency,
		Timeout:     *timeout,
		Output:      *output,
		MaxRetries:  *maxRetries,
		LogLevel:    *logLevel,
		OutputDir:   *outputDir,
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

// Increment 增加进度计数
func (p *Progress) Increment() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.Processed++
	
	if p.logLevel >= LogLevelNormal {
		percentage := float64(p.Processed*100) / float64(p.Total)
		if p.Processed%10 == 0 || p.Processed == p.Total {
			fmt.Fprintf(os.Stderr, "\r处理进度: %d/%d (%.1f%%) ", p.Processed, p.Total, percentage)
			if p.Processed == p.Total {
				fmt.Fprintln(os.Stderr, "✓ 完成")
			}
		}
	}
}

// processResults 处理检测结果
func processResults(ctx context.Context, results <-chan Result, writer io.Writer, progress *Progress, logLevel LogLevel) ([]Channel, *Stats, error) {
	var availableChannels []Channel
	stats := &Stats{}

	if logLevel >= LogLevelNormal {
		fmt.Fprintf(writer, "\n结果:\n")
	}

	// 按来源分离结果并实时处理
	localResults := make([]Result, 0)
	networkResults := make([]Result, 0)

	// 收集结果
	for result := range results {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("操作被取消: %w", ctx.Err())
		default:
		}

		// 更新进度
		progress.Increment()

		if result.Channel.Source == "local" {
			if result.Available {
				stats.LocalAvailable++
				availableChannels = append(availableChannels, result.Channel)
			} else {
				stats.LocalUnavailable++
			}
			localResults = append(localResults, result)
		} else {
			if result.Available {
				stats.NetworkAvailable++
				availableChannels = append(availableChannels, result.Channel)
			} else {
				stats.NetworkUnavailable++
			}
			networkResults = append(networkResults, result)
		}
	}

	// 显示本地结果
	if logLevel >= LogLevelNormal {
		fmt.Fprintf(writer, "\n--- 本地频道 ---\n")
		for _, result := range localResults {
			if result.Available {
				if logLevel >= LogLevelVerbose {
					fmt.Fprintf(writer, "✓ %s - %s (响应时间: %v)\n", result.Channel.Name, result.Channel.URL, result.ResponseTime)
				} else {
					fmt.Fprintf(writer, "✓ %s - %s\n", result.Channel.Name, result.Channel.URL)
				}
			} else {
				// 避免输出可能包含乱码的错误信息
				if result.Error != nil {
					// 只输出错误类型，不输出具体错误内容
					fmt.Fprintf(writer, "✗ %s - %s (错误: %s)\n", result.Channel.Name, result.Channel.URL, "连接失败")
				} else {
					fmt.Fprintf(writer, "✗ %s - %s\n", result.Channel.Name, result.Channel.URL)
				}
			}
		}

		// 显示网络结果
		fmt.Fprintf(writer, "\n--- 网络频道 ---\n")
		for _, result := range networkResults {
			if result.Available {
				if logLevel >= LogLevelVerbose {
					fmt.Fprintf(writer, "✓ %s - %s (响应时间: %v)\n", result.Channel.Name, result.Channel.URL, result.ResponseTime)
				} else {
					fmt.Fprintf(writer, "✓ %s - %s\n", result.Channel.Name, result.Channel.URL)
				}
			} else {
				// 避免输出可能包含乱码的错误信息
				if result.Error != nil {
					// 只输出错误类型，不输出具体错误内容
					fmt.Fprintf(writer, "✗ %s - %s (错误: %s)\n", result.Channel.Name, result.Channel.URL, "连接失败")
				} else {
					fmt.Fprintf(writer, "✗ %s - %s\n", result.Channel.Name, result.Channel.URL)
				}
			}
		}
	}

	return availableChannels, stats, nil
}

// displayStats 显示统计信息
func displayStats(stats *Stats, writer io.Writer) {
	fmt.Fprintf(writer, "\n摘要:\n")
	fmt.Fprintf(writer, "本地频道 - 可用: %d, 不可用: %d\n", stats.LocalAvailable, stats.LocalUnavailable)
	fmt.Fprintf(writer, "网络频道 - 可用: %d, 不可用: %d\n", stats.NetworkAvailable, stats.NetworkUnavailable)
	fmt.Fprintf(writer, "总计 - 可用: %d, 不可用: %d\n", stats.LocalAvailable+stats.NetworkAvailable, stats.LocalUnavailable+stats.NetworkUnavailable)
}

// loadGroupConfig 从文件加载分组配置
func loadGroupConfig(filePath string) (*GroupConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config GroupConfig
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	// 预编译正则表达式
	if config.RegexGroups != nil {
		config.CompiledRegex = make(map[string]*regexp.Regexp)
		for group, pattern := range config.RegexGroups {
			re, err := regexp.Compile(pattern)
			if err != nil {
				fmt.Printf("警告: 正则表达式编译失败 (%s): %v\n", pattern, err)
				continue
			}
			config.CompiledRegex[group] = re
		}
	}

	return &config, nil
}

// getDefaultGroupConfig 获取默认分组配置
func getDefaultGroupConfig() *GroupConfig {
	return &GroupConfig{
		Groups: map[string][]string{
			"央视": {"央视", "CCTV"},
			"卫视": {"卫视"},
			"新闻": {"新闻"},
			"体育": {"体育", "足球", "篮球"},
			"影视": {"影视"},
			"电影": {"电影"},
			"音乐": {"音乐"},
			"少儿": {"少儿"},
			"动漫": {"动漫"},
			"纪录": {"纪录"},
			"科教": {"科教"},
			"财经": {"财经"},
			"农业": {"农业"},
			"戏曲": {"戏曲"},
			"生活": {"生活"},
			"社会": {"社会"},
			"法制": {"法制"},
			"军事": {"军事"},
			"旅游": {"旅游"},
			"娱乐": {"娱乐"},
			"游戏": {"游戏"},
			"美食": {"美食"},
			"时尚": {"时尚"},
			"电竞": {"电竞"},
			"直播": {"直播"},
			"斗鱼": {"斗鱼"},
			"虎牙": {"虎牙"},
			"哔哩": {"哔哩", "B站", "哔哩哔哩"},
		},
		RegexGroups:   make(map[string]string),
		CompiledRegex: make(map[string]*regexp.Regexp),
		GroupOrder: []string{
			"央视", "卫视", "新闻", "体育", "影视", "电影", "音乐", "少儿", "动漫",
			"纪录", "科教", "财经", "农业", "戏曲", "生活", "社会", "法制", "军事",
			"旅游", "娱乐", "游戏", "美食", "时尚", "电竞", "直播", "斗鱼", "虎牙", "哔哩",
		},
	}
}

// 标记非重试性错误（例如 403/404 等）
type nonRetryableError struct{ msg string }

func (e nonRetryableError) Error() string { return e.msg }
func nonRetryable(msg string) error      { return nonRetryableError{msg: msg} }
func isNonRetryable(err error) bool {
	var e nonRetryableError
	return errors.As(err, &e)
}

// readAllChannels 从本地文件和URL读取频道
func readAllChannels(filePath, urls, urlFile string, logger *Logger) ([]Channel, []Channel, error) {
	var localChannels []Channel
	var networkChannels []Channel

	// 如果本地文件存在则读取
	if _, err := os.Stat(filePath); err == nil {
		channels, err := readChannelsFromFile(filePath)
		if err != nil {
			logger.Warn("读取本地文件时出错: %v", err)
		} else {
			// 标记所有本地频道
			for i := range channels {
				channels[i].Source = "local"
			}
			localChannels = append(localChannels, channels...)
			logger.Info("从本地文件 %s 加载了 %d 个频道", filePath, len(channels))
		}
	} else {
		logger.Info("未找到本地文件 %s，跳过", filePath)
	}

	// 如果提供了URL则读取
	if urls != "" {
		urlList := strings.Split(urls, ",")
		for _, u := range urlList {
			u = strings.TrimSpace(u)
			if u != "" {
				channels, err := readChannelsFromURL(u)
				if err != nil {
					logger.Warn("从 URL %s 读取时出错: %v", u, err)
				} else {
					// 标记所有网络频道
					for i := range channels {
						channels[i].Source = "network"
					}
					networkChannels = append(networkChannels, channels...)
					logger.Info("从 URL %s 加载了 %d 个频道", u, len(channels))
				}
			}
		}
	}

	// 如果提供了URL文件则读取
	if urlFile != "" {
		urlList, err := readURLsFromFile(urlFile)
		if err != nil {
			logger.Warn("从文件 %s 读取URL时出错: %v", urlFile, err)
		} else {
			for _, u := range urlList {
				channels, err := readChannelsFromURL(u)
				if err != nil {
					logger.Warn("从 URL %s 读取时出错: %v", u, err)
				} else {
					// 标记所有网络频道
					for i := range channels {
						channels[i].Source = "network"
					}
					networkChannels = append(networkChannels, channels...)
					logger.Info("从 URL %s 加载了 %d 个频道", u, len(channels))
				}
			}
		}
	}

	return localChannels, networkChannels, nil
}

// readURLsFromFile 从文件读取URL列表
func readURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	return urls, scanner.Err()
}

// readChannelsFromFile 从本地文件读取频道
func readChannelsFromFile(filePath string) ([]Channel, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件: %w", err)
	}
	defer file.Close()

	return parseChannels(file)
}

// readChannelsFromURL 从URL读取频道
func readChannelsFromURL(url string) ([]Channel, error) {
	client := createHTTPClient(30 * time.Second)

	// 先尝试 HEAD，失败或不支持再 GET
	req, _ := http.NewRequest("HEAD", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")
	resp, err := client.Do(req)
	if err == nil && resp != nil {
		if resp.Body != nil { resp.Body.Close() }
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// 认为可读取内容
		} else if resp.StatusCode == 403 || resp.StatusCode == 404 {
			return nil, fmt.Errorf("获取URL失败: %d", resp.StatusCode)
		}
	}

	req2, _ := http.NewRequest("GET", url, nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	req2.Header.Set("Accept", "*/*")
	req2.Header.Set("Connection", "close")
	resp2, err := client.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("获取URL失败: %w", err)
	}
	defer func() {
		if resp2.Body != nil { resp2.Body.Close() }
	}()

	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取URL时HTTP状态码为 %d", resp2.StatusCode)
	}

	return parseChannels(resp2.Body)
}

// createHTTPClient 创建优化的HTTP客户端
func createHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableCompression:    true,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// parseChannels 从io.Reader解析频道
func parseChannels(reader io.Reader) ([]Channel, error) {
	var channels []Channel
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "#EXTINF:") {
			if scanner.Scan() {
				urlLine := strings.TrimSpace(scanner.Text())
				name := extractChannelName(line)
				if isValidURL(urlLine) {
					channels = append(channels, Channel{Name: name, URL: urlLine})
				}
			}
		} else if strings.HasSuffix(line, ",#genre#") {
			continue
		} else {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				if isValidURL(parts[1]) {
					channels = append(channels, Channel{Name: parts[0], URL: parts[1]})
				}
			} else if len(parts) == 1 && isValidURL(parts[0]) {
				u, err := url.Parse(parts[0])
				name := parts[0]
				if err == nil {
					name = u.Host
				}
				channels = append(channels, Channel{Name: name, URL: parts[0]})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取频道时出错: %w", err)
	}

	return channels, nil
}

// extractChannelName 从EXTINF行提取频道名称
func extractChannelName(extinfLine string) string {
	tvgNameStart := strings.Index(extinfLine, `tvg-name="`)
	if tvgNameStart != -1 {
		tvgNameStart += len(`tvg-name="`)
		tvgNameEnd := strings.Index(extinfLine[tvgNameStart:], `"`)
		if tvgNameEnd != -1 {
			return extinfLine[tvgNameStart : tvgNameStart+tvgNameEnd]
		}
	}

	lastComma := strings.LastIndex(extinfLine, ",")
	if lastComma != -1 && lastComma < len(extinfLine)-1 {
		return extinfLine[lastComma+1:]
	}

	return "未知频道"
}

// isValidURL 检查字符串是否为有效URL
func isValidURL(s string) bool {
	if s == "" {
		return false
	}

	u, err := url.Parse(s)
	if err != nil {
		return false
	}

	// 检查协议
	supportedSchemes := map[string]bool{
		"http":  true,
		"https": true,
		"rtmp":  true,
		"rtsp":  true,
		"mms":   true,
		"udp":   true,
		"rtp":   true,
	}

	if !supportedSchemes[strings.ToLower(u.Scheme)] {
		return false
	}

	// 检查主机名
	if u.Host == "" {
		return false
	}

	return true
}

// removeDuplicates 去除重复频道
func removeDuplicates(channels []Channel) []Channel {
	seen := make(map[string]bool)
	result := make([]Channel, 0)

	for _, channel := range channels {
		key := channel.Name + "|" + channel.URL
		if !seen[key] {
			seen[key] = true
			result = append(result, channel)
		}
	}

	return result
}

// worker 工作线程，处理频道检查任务
func worker(wg *sync.WaitGroup, jobs <-chan Channel, results chan<- Result, timeout time.Duration, maxRetries int, progress *Progress) {
	defer wg.Done()

	client := createHTTPClient(timeout)

	for channel := range jobs {
		available, responseTime, err := checkChannel(client, channel, maxRetries)
		results <- Result{
			Channel:      channel,
			Available:    available,
			ResponseTime: responseTime,
			Error:        err,
		}
	}
}

// checkChannel 检查频道是否可用
func checkChannel(client *http.Client, channel Channel, maxRetries int) (bool, time.Duration, error) {
	if !isValidURL(channel.URL) {
		return false, 0, fmt.Errorf("无效的URL")
	}

	u, err := url.Parse(channel.URL)
	if err != nil {
		return false, 0, err
	}

	switch u.Scheme {
	case "http", "https":
		return checkHTTPStream(client, channel.URL, maxRetries)
	case "rtmp", "rtsp", "mms", "udp", "rtp":
		return true, 0, nil
	default:
		return false, 0, fmt.Errorf("不支持的协议: %s", u.Scheme)
	}
}

// checkHTTPStream 检查HTTP/HTTPS流是否可用，支持重试
func checkHTTPStream(client *http.Client, url string, maxRetries int) (bool, time.Duration, error) {
	var lastError error
	var lastDuration time.Duration

	for i := 0; i < maxRetries; i++ {
		available, duration, err := attemptHTTPRequest(client, url)
		if available {
			return true, duration, nil
		}
		lastError = err
		lastDuration = duration

		// 非重试性错误直接返回
		if err != nil && isNonRetryable(err) {
			return false, duration, err
		}

		if i < maxRetries-1 {
			// 退避等待：1s, 2s, 3s ...
			time.Sleep(time.Second * time.Duration(i+1))
		}
	}

	return false, lastDuration, lastError
}

// attemptHTTPRequest 尝试发送HTTP GET请求
func attemptHTTPRequest(client *http.Client, url string) (bool, time.Duration, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置更完整的请求头
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return false, duration, fmt.Errorf("请求超时")
		}
		return false, duration, fmt.Errorf("请求失败: %w", err)
	}

	// 直播类响应不读尽，直接关闭
	if resp.Body != nil { resp.Body.Close() }

	// 更详细的状态码处理 + 内容类型粗过滤
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(ct, "text/html") {
			return false, duration, nonRetryable("返回 HTML 页面，可能需要鉴权")
		}
		return true, duration, nil
	case resp.StatusCode == 403:
		return false, duration, nonRetryable("访问被拒绝 (403)")
	case resp.StatusCode == 404:
		return false, duration, nonRetryable("资源不存在 (404)")
	case resp.StatusCode >= 500:
		return false, duration, fmt.Errorf("服务器错误 (%d)", resp.StatusCode)
	default:
		return false, duration, fmt.Errorf("HTTP状态码 %d", resp.StatusCode)
	}
}

// assignGroup 根据频道名称为频道分配组别，支持关键字和正则表达式匹配
func assignGroup(channel Channel, groupConfig *GroupConfig) string {
	// 关键字匹配
	for group, keywords := range groupConfig.Groups {
		for _, keyword := range keywords {
			if strings.Contains(channel.Name, keyword) {
				return group
			}
		}
	}

	// 正则表达式匹配（使用预编译的正则表达式）
	for group, re := range groupConfig.CompiledRegex {
		if re.MatchString(channel.Name) {
			return group
		}
	}

	return "其他"
}

// saveAvailableChannels 将可用频道保存到public文件夹中的txt和m3u格式文件
func saveAvailableChannels(channels []Channel, groupConfig *GroupConfig, logLevel LogLevel, dir string) error {
	if dir == "" {
		dir = "public"
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	localChannels := make([]Channel, 0)
	networkChannels := make([]Channel, 0)

	for _, channel := range channels {
		if channel.Source == "local" {
			localChannels = append(localChannels, channel)
		} else {
			networkChannels = append(networkChannels, channel)
		}
	}

	orderedChannels := append(localChannels, networkChannels...)

	// 保存txt格式
	txtFile, err := os.Create(dir + "/live.txt")
	if err != nil {
		return fmt.Errorf("创建live.txt失败: %w", err)
	}
	defer txtFile.Close()

	txtWriter := bufio.NewWriter(txtFile)
	for _, channel := range orderedChannels {
		fmt.Fprintf(txtWriter, "%s,%s\n", channel.Name, channel.URL)
	}
	txtWriter.Flush()

	// 保存m3u格式
	m3uFile, err := os.Create(dir + "/live.m3u")
	if err != nil {
		return fmt.Errorf("创建live.m3u失败: %w", err)
	}
	defer m3uFile.Close()

	m3uWriter := bufio.NewWriter(m3uFile)
	fmt.Fprintln(m3uWriter, "#EXTM3U")

	groupedChannels := make(map[string][]Channel)
	others := make([]Channel, 0)

	for _, channel := range orderedChannels {
		group := assignGroup(channel, groupConfig)
		if group == "其他" {
			others = append(others, channel)
		} else {
			groupedChannels[group] = append(groupedChannels[group], channel)
		}
	}

	// 按照配置的组别顺序输出
	for _, groupName := range groupConfig.GroupOrder {
		channelsInGroup := groupedChannels[groupName]
		if len(channelsInGroup) > 0 {
			fmt.Fprintf(m3uWriter, "#EXTGRP:%s\n", groupName)
			for _, channel := range channelsInGroup {
				fmt.Fprintf(m3uWriter, "#EXTINF:-1 tvg-name=\"%s\" tvg-id=\"%s\" tvg-logo=\"%s\" group-title=\"%s\",%s\n%s\n", 
					channel.Name, channel.Name, "", groupName, channel.Name, channel.URL)
			}
		}
	}

	// 输出其他组别
	if len(others) > 0 {
		fmt.Fprintf(m3uWriter, "#EXTGRP:其他\n")
		for _, channel := range others {
			fmt.Fprintf(m3uWriter, "#EXTINF:-1 tvg-name=\"%s\" tvg-id=\"%s\" tvg-logo=\"%s\" group-title=\"其他\",%s\n%s\n", 
				channel.Name, channel.Name, "", channel.Name, channel.URL)
		}
	}

	m3uWriter.Flush()

	if logLevel >= LogLevelVerbose {
		fmt.Printf("已保存 %d 个可用频道到 %s 目录\n", len(orderedChannels), dir)
	}

	return nil
}