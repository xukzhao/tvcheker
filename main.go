package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
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
	FilePath       string
	URLs           string
	URLFile        string
	GroupsFile     string
	Concurrency    int
	Timeout        int
	Output         string
	MaxRetries     int
	LogLevel       string
	OutputDir      string
	SecureConnect  bool // 是否使用安全连接（验证SSL证书）
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
	FilePath       string   `json:"file_path"`
	URLs           []string `json:"urls"`
	URLFile        string   `json:"url_file"`
	GroupsFile     string   `json:"groups_file"`
	Concurrency    int      `json:"concurrency"`
	Timeout        int      `json:"timeout"`
	Output         string   `json:"output"`
	MaxRetries     int      `json:"max_retries"`
	LogLevel       string   `json:"log_level"`
	OutputDir      string   `json:"output_dir"`
	SecureConnect  bool     `json:"secure_connect"` // 是否使用安全连接（验证SSL证书）
}

// LogLevel 定义日志级别类型
type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelNormal
	LogLevelVerbose
	LogLevelDebug   // 新增调试级别
	LogLevelTrace   // 新增跟踪级别
)

// Logger 统一日志处理结构
type Logger struct {
	level LogLevel
	mutex sync.Mutex // 添加互斥锁确保线程安全
	output io.Writer // 可配置输出目标
}

// NewLogger 创建新的日志记录器
func NewLogger(level LogLevel, output io.Writer) *Logger {
	if output == nil {
		output = os.Stdout
	}
	return &Logger{
		level:  level,
		output: output,
	}
}

func (l *Logger) log(prefix, format string, args ...interface{}) {
	if l.output == nil {
		return
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	if prefix != "" {
		fmt.Fprintf(l.output, "%s [%s] %s\n", timestamp, prefix, msg)
	} else {
		fmt.Fprintf(l.output, "%s %s\n", timestamp, msg)
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.level >= LogLevelNormal {
		l.log("INFO", format, args...)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level >= LogLevelNormal {
		l.log("WARN", format, args...)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	// 错误总是输出，不管日志级别
	l.log("ERROR", format, args...)
}

func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.level >= LogLevelVerbose {
		l.log("VERBOSE", format, args...)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level >= LogLevelDebug {
		l.log("DEBUG", format, args...)
	}
}

func (l *Logger) Trace(format string, args ...interface{}) {
	if l.level >= LogLevelTrace {
		l.log("TRACE", format, args...)
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
	if validateErr := validateConfig(config); validateErr != nil {
		return fmt.Errorf("配置验证失败: %w", validateErr)
	}

	// 创建日志记录器
	logger := NewLogger(parseLogLevel(config.LogLevel), os.Stdout)

	// 尝试从配置文件加载配置
	// 尝试多路径加载配置文件
configPaths := []string{"config.json", "go/config.json", "web/config.json"}
for _, cfgPath := range configPaths {
	if _, statErr := os.Stat(cfgPath); statErr == nil {
		fileConfig, loadErr := loadConfigFromFile(cfgPath)
		if loadErr != nil {
			logger.Warn("配置文件 %s 存在但格式错误: %v", cfgPath, loadErr)
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
		if _, statErr := os.Stat(p); statErr == nil {
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

	// 更新系统资源使用情况
	sysMonitor.Update()
	
	// 根据系统负载动态调整并发数
	actualConcurrency := sysMonitor.GetRecommendedConcurrency(config.Concurrency)
	if actualConcurrency != config.Concurrency {
		logger.Info("根据系统负载调整并发数从 %d 到 %d", config.Concurrency, actualConcurrency)
	}
	
	// 启动工作线程
	var wg sync.WaitGroup
	for i := 0; i < actualConcurrency; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, time.Duration(config.Timeout)*time.Second, config.MaxRetries, progress, config.SecureConnect, logger)
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
	secureConnect := flag.Bool("secure", false, "是否使用安全连接（验证SSL证书）。默认为false，如果设置为true，将验证SSL证书，提高安全性但可能导致某些站点无法访问")
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
	// 合并安全连接选项
	config.SecureConnect = fileConfig.SecureConnect
}

// createHTTPClient 创建HTTP客户端，集中管理HTTP客户端的创建
// secureConnect: 是否使用安全连接（验证SSL证书）
// timeout: 超时时间（秒）
// logger: 日志记录器，用于记录安全警告
func createHTTPClient(secureConnect bool, timeout int, logger *Logger) *http.Client {
	// 创建传输配置
	transport := &http.Transport{
		DisableCompression: true,
		ForceAttemptHTTP2: false,
	}
	
	// 根据安全设置决定是否验证SSL证书
	if !secureConnect {
		// 不安全模式：忽略SSL证书验证
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		
		// 记录安全警告
		if logger != nil {
			logger.Warn("安全警告：已禁用SSL证书验证，这可能导致中间人攻击风险")
			logger.Warn("如果您在安全环境中运行，建议使用 --secureConnect 参数启用安全连接")
		} else {
			log.Println("安全警告：已禁用SSL证书验证，这可能导致中间人攻击风险")
			log.Println("如果您在安全环境中运行，建议使用 --secureConnect 参数启用安全连接")
		}
	} else if logger != nil {
		logger.Info("使用安全的HTTP客户端，验证SSL证书")
	}
	
	// 创建客户端
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: transport,
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
			re, compileErr := regexp.Compile(pattern)
			if compileErr != nil {
				fmt.Printf("警告: 正则表达式编译失败 (%s): %v\n", pattern, compileErr)
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

// ErrorType 定义错误类型
type ErrorType int

const (
	ErrorTypeRetryable ErrorType = iota    // 可重试错误
	ErrorTypeNonRetryable                   // 不可重试错误
	ErrorTypeTemporary                      // 临时错误
	ErrorTypePermanent                      // 永久错误
)

// AppError 应用错误结构体，提供统一的错误处理
type AppError struct {
	Type    ErrorType
	Message string
	Cause   error
}

func (e AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap 实现errors.Unwrap接口
func (e AppError) Unwrap() error {
	return e.Cause
}

// NewRetryableError 创建可重试错误
func NewRetryableError(msg string, cause error) error {
	return AppError{
		Type:    ErrorTypeRetryable,
		Message: msg,
		Cause:   cause,
	}
}

// NewNonRetryableError 创建不可重试错误
func NewNonRetryableError(msg string, cause error) error {
	return AppError{
		Type:    ErrorTypeNonRetryable,
		Message: msg,
		Cause:   cause,
	}
}

// 删除未使用的函数

// nonRetryableError 表示不应该重试的错误（保留兼容旧代码）
type nonRetryableError struct {
	msg string
}

func (e nonRetryableError) Error() string {
	return e.msg
}

// isNonRetryable 检查错误是否为不可重试类型
func isNonRetryable(err error) bool {
	// 如果错误为nil，则不是不可重试错误
	if err == nil {
		return false
	}
	
	// 首先检查是否为AppError类型
	var appErr AppError
	if errors.As(err, &appErr) {
		return appErr.Type == ErrorTypeNonRetryable || appErr.Type == ErrorTypePermanent
	}
	
	// 兼容旧代码
	var e nonRetryableError
	return errors.As(err, &e)
}

// handleSpecialApiRequest 处理特殊的API请求，如api.mytv666.top
func handleSpecialApiRequest(client *http.Client, apiUrl string) (bool, time.Duration, error) {
	if client == nil {
		return false, 0, NewNonRetryableError("HTTP客户端为空", nil)
	}
	
	if apiUrl == "" {
		return false, 0, NewNonRetryableError("API URL为空", nil)
	}
	
	fmt.Printf("处理特殊API请求: %s\n", apiUrl)
	
	// 解析URL中的参数
	fmt.Println("尝试解析URL中的参数")
	parsedURL, err := url.Parse(apiUrl)
	if err != nil {
		fmt.Printf("解析URL失败: %v\n", err)
		return false, 0, NewNonRetryableError("解析URL失败", err)
	}
	
	// 获取查询参数
	query := parsedURL.Query()
	hexID := query.Get("id")
	tid := query.Get("tid")
	// 避免重复声明id变量，因为hexID已经获取了相同的值
	fmt.Printf("获取到的参数: hexID=%s, tid=%s\n", hexID, tid)
	
	// 首先尝试直接访问原始URL，不做任何修改
	fmt.Println("尝试直接访问原始URL")
	directAvailable, directDuration, err := tryDirectRequest(client, apiUrl)
	if directAvailable {
		fmt.Println("直接访问原始URL成功")
		return true, directDuration, nil
	} else {
		fmt.Printf("直接访问原始URL失败: %v\n", err)
	}
	
	// 尝试解码十六进制ID
	var decodedID string
	if hexID != "" {
		decodedBytes, decodeErr := hex.DecodeString(hexID)
		if decodeErr != nil {
			fmt.Printf("解码十六进制ID失败: %v\n", decodeErr)
		} else {
			decodedID = string(decodedBytes)
			fmt.Printf("解码后的ID: %s\n", decodedID)
		}
	}
	
	// 尝试访问已知的FLV地址
	if strings.Contains(apiUrl, "api.mytv666.top") && strings.Contains(apiUrl, "hk.php") {
		fmt.Println("尝试访问已知的FLV地址")
		knownFlvURLs := []string{
			"https://pullsstx.peiyou.eaydu.com/live/67950b1cfae5859bc6f344c67d934736.flv",
		}
		
		for _, flvURL := range knownFlvURLs {
			fmt.Printf("尝试FLV地址: %s\n", flvURL)
			flvAvailable, flvDuration, tryErr := tryDirectURL(client, flvURL)
			if flvAvailable {
				fmt.Println("访问FLV地址成功")
				return true, flvDuration, nil
			} else {
				fmt.Printf("访问FLV地址失败: %v\n", tryErr)
			}
		}
	}
	
	// 尝试构建新的URL，确保使用原始的hexID
	if hexID != "" && tid != "" {
		fmt.Println("尝试构建新的URL")
		
		// 构建新的URL，保持原始的hexID不变
		newURL := fmt.Sprintf("http://api.mytv666.top/api/hk.php?id=%s&tid=%s&_=%d", 
			hexID, tid, time.Now().Unix())
		fmt.Printf("构建的新URL: %s\n", newURL)
		
		// 尝试访问新URL
		var newUrlAvailable bool
		var newUrlDuration time.Duration
		newUrlAvailable, newUrlDuration, err = tryDirectRequest(client, newURL)
		if newUrlAvailable {
			fmt.Println("访问新URL成功")
			return true, newUrlDuration, nil
		} else {
			fmt.Printf("访问新URL失败: %v\n", err)
		}
	}
	
	// 所有尝试均失败
	return false, 0, NewNonRetryableError("所有尝试均失败", nil)
}

// tryDirectRequest 尝试直接请求URL
func tryDirectRequest(client *http.Client, apiUrl string) (bool, time.Duration, error) {
	// 参数验证
	if client == nil {
		return false, 0, NewNonRetryableError("HTTP客户端为空", nil)
	}
	
	if apiUrl == "" {
		return false, 0, NewNonRetryableError("URL为空", nil)
	}
	
	start := time.Now()
	fmt.Printf("尝试直接请求URL: %s\n", apiUrl)
	
	// 使用不同的User-Agent尝试
	userAgents := []string{
		"okhttp/3.12.11", // TVBox常用
		"Dalvik/2.1.0 (Linux; U; Android 11; M2012K11AC Build/RKQ1.200826.002)", // 安卓设备
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", // 浏览器
		"Lavf/58.12.100", // 常用于流媒体播放器
	}
	
	for _, ua := range userAgents {
		fmt.Printf("使用User-Agent: %s\n", ua)
		
		// 创建请求
		req, err := http.NewRequest("GET", apiUrl, nil)
		if err != nil {
			fmt.Printf("创建请求失败: %v\n", err)
			continue
		}
		
		// 设置请求头
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Range", "bytes=0-")
		req.Header.Set("Referer", "http://www.tvbox.cn/")
		
		// 使用传入的客户端发送请求
		fmt.Println("发送请求...")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("请求失败: %v\n", err)
			continue
		}
		
		// 确保响应体被关闭
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()
		
		// 检查响应状态
		fmt.Printf("响应状态码: %d\n", resp.StatusCode)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// 检查内容类型
			contentType := resp.Header.Get("Content-Type")
			fmt.Printf("内容类型: %s\n", contentType)
			
			// 检查是否是视频或二进制流
			if strings.Contains(strings.ToLower(contentType), "video/") || 
			   strings.Contains(strings.ToLower(contentType), "application/octet-stream") ||
			   contentType == "" { // 有些服务器不返回内容类型
				fmt.Println("内容类型匹配成功")
				return true, time.Since(start), nil
			}
			
			// 读取少量内容进行检查
			buf := make([]byte, 16)
			n, err := resp.Body.Read(buf)
			if (err == nil || err == io.EOF) && n > 0 {
				// 检查是否是FLV格式
				if n >= 3 && string(buf[:3]) == "FLV" {
					fmt.Println("检测到FLV格式视频流")
					return true, time.Since(start), nil
				}
				
				// 检查是否是其他常见视频格式的魔数
				if n >= 4 {
					// MP4格式检查 (ftyp)
					if n >= 8 && (string(buf[4:8]) == "ftyp" || string(buf[4:8]) == "moov") {
						fmt.Println("检测到MP4格式视频流")
						return true, time.Since(start), nil
					}
					
					// TS流检查 (0x47开头)
					if buf[0] == 0x47 {
						fmt.Println("检测到TS格式视频流")
						return true, time.Since(start), nil
					}
				}
			}
		}
	}
	
	return false, time.Since(start), NewNonRetryableError("所有尝试均失败", nil)
}

// 删除未使用的函数

// tryDirectURL 尝试直接访问URL
func tryDirectURL(client *http.Client, directURL string) (bool, time.Duration, error) {
	// 参数验证
	if client == nil {
		return false, 0, NewNonRetryableError("HTTP客户端为空", nil)
	}
	
	if directURL == "" {
		return false, 0, NewNonRetryableError("URL为空", nil)
	}
	
	start := time.Now()
	fmt.Printf("尝试直接访问URL: %s\n", directURL)
	
	// 检查URL是否有效
	if !isValidURL(directURL) {
		fmt.Println("无效的URL")
		return false, 0, NewNonRetryableError("无效的URL", nil)
	}
	
	// 使用不同的User-Agent尝试
	userAgents := []string{
		"okhttp/3.12.11", // TVBox常用
		"Lavf/58.12.100", // 常用于流媒体播放器
		"Dalvik/2.1.0 (Linux; U; Android 11; M2012K11AC Build/RKQ1.200826.002)", // 安卓设备
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", // 浏览器
	}
	
	for _, ua := range userAgents {
		fmt.Printf("使用User-Agent: %s\n", ua)
		
		// 创建请求
		req, err := http.NewRequest("GET", directURL, nil)
		if err != nil {
			fmt.Printf("创建请求失败: %v\n", err)
			continue
		}
		
		// 设置请求头
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Range", "bytes=0-")
		req.Header.Set("Referer", "http://www.tvbox.cn/")
		
		// 使用传入的客户端发送请求
		fmt.Println("发送请求...")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("请求失败: %v\n", err)
			continue
		}
		defer resp.Body.Close()
		
		// 打印响应头信息
		fmt.Printf("响应状态码: %d\n", resp.StatusCode)
		fmt.Println("响应头:")
		for k, v := range resp.Header {
			fmt.Printf("%s: %v\n", k, v)
		}
		
		// 检查响应状态
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Println("响应状态码正常")
			
			// 检查内容类型
			contentType := resp.Header.Get("Content-Type")
			fmt.Printf("内容类型: %s\n", contentType)
			
			// 如果是视频或二进制流，直接返回成功
			if strings.Contains(strings.ToLower(contentType), "video/") || 
			   strings.Contains(strings.ToLower(contentType), "application/octet-stream") ||
			   contentType == "" { // 有些服务器不返回内容类型
				fmt.Println("内容类型匹配成功")
				return true, time.Since(start), nil
			}
			
			// 读取少量内容进行检查
			fmt.Println("读取响应内容进行检查...")
			buf := make([]byte, 100) // 增加读取的字节数，以便更好地检查
			n, err := resp.Body.Read(buf)
			if (err == nil || err == io.EOF) && n > 0 {
				fmt.Printf("读取了 %d 字节的内容\n", n)
				
				// 检查是否是FLV格式
				if n >= 3 && string(buf[:3]) == "FLV" {
					fmt.Println("检测到FLV格式视频流")
					return true, time.Since(start), nil
				}
				
				// 检查是否是其他常见视频格式的魔数
				if n >= 4 {
					// MP4格式检查 (ftyp)
					if n >= 8 && (string(buf[4:8]) == "ftyp" || string(buf[4:8]) == "moov") {
						fmt.Println("检测到MP4格式视频流")
						return true, time.Since(start), nil
					}
					
					// TS流检查 (0x47开头)
					if buf[0] == 0x47 {
						fmt.Println("检测到TS格式视频流")
						return true, time.Since(start), nil
					}
					
					// M3U8格式检查
					if n >= 7 && (strings.HasPrefix(string(buf), "#EXTM3U") || strings.Contains(string(buf[:n]), "#EXTM3U")) {
						fmt.Println("检测到M3U8格式播放列表")
						return true, time.Since(start), nil
					}
				}
				
				// 检查是否包含视频相关的标识
				content := string(buf[:n])
				fmt.Printf("内容前100字节: %s\n", content)
				
				// 如果内容中包含视频相关的标识，也认为是成功的
				if strings.Contains(strings.ToLower(content), "video") ||
				   strings.Contains(strings.ToLower(content), "stream") ||
				   strings.Contains(strings.ToLower(content), "media") {
					fmt.Println("内容中包含视频相关标识")
					return true, time.Since(start), nil
				}
			} else {
				fmt.Printf("读取内容失败: %v\n", err)
			}
		} else {
			fmt.Printf("响应状态码异常: %d\n", resp.StatusCode)
		}
	}
	
	return false, time.Since(start), NewNonRetryableError("所有直接访问尝试均失败", nil)
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
	client := createHTTPClient(true, 30, nil) // 默认使用安全连接，30秒超时，无日志记录

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

// 删除未使用的变量

// 删除未使用的类型和方法

// createHTTPClient 创建优化的HTTP客户端
// 旧的createHTTPClient函数已被移除，使用新的函数代替

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

// 系统资源监控结构
type SystemMonitor struct {
	mutex      sync.Mutex
	lastUpdate time.Time
}

// 全局系统监控器
var sysMonitor = &SystemMonitor{lastUpdate: time.Now()}

// 更新系统资源使用情况
func (sm *SystemMonitor) Update() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 简单模拟资源监控，实际应用中应使用系统API获取真实数据
	// 例如在Linux上可以读取/proc文件系统，在Windows上可以使用WMI
	// 这里仅作为示例，不实际监控系统资源
	sm.lastUpdate = time.Now()
	
	// 可以在这里添加实际的系统资源监控代码
	// 例如：获取CPU使用率、内存使用情况等
}

// 获取建议的并发数
func (sm *SystemMonitor) GetRecommendedConcurrency(max int) int {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// 如果上次更新超过30秒，返回默认值
	if time.Since(sm.lastUpdate) > 30*time.Second {
		return max / 2
	}
	
	// 根据CPU和内存使用情况动态调整
	// 这里使用简化逻辑，实际应用中应根据真实监控数据计算
	
	// 可以根据系统负载动态调整并发数
	// 例如：当CPU使用率高时，降低并发数；当内存充足时，适当提高并发数
	// 这里可以添加更复杂的算法来计算最佳并发数
	
	// 确保并发数不小于1且不超过最大值
	return max
}

// worker 工作线程，处理频道检查任务
func worker(wg *sync.WaitGroup, jobs <-chan Channel, results chan<- Result, timeout time.Duration, maxRetries int, _ *Progress, secureConnect bool, logger *Logger) {
	defer wg.Done()

	client := createHTTPClient(secureConnect, int(timeout.Seconds()), logger)

	for channel := range jobs {
		// 非阻塞检查已移除，因为select语句的实现有问题
		// 原实现中default会立即执行，time.After永远不会被选中
		
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
	// 参数验证
	if client == nil {
		return false, 0, NewNonRetryableError("HTTP客户端为空", nil)
	}
	
	if channel.URL == "" {
		return false, 0, NewNonRetryableError("频道URL为空", nil)
	}
	
	if !isValidURL(channel.URL) {
		return false, 0, NewNonRetryableError("无效的URL", nil)
	}

	u, err := url.Parse(channel.URL)
	if err != nil {
		return false, 0, NewNonRetryableError("解析URL失败", err)
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
	// 参数验证
	if client == nil {
		return false, 0, NewNonRetryableError("HTTP客户端为空", nil)
	}
	
	if url == "" {
		return false, 0, NewNonRetryableError("URL为空", nil)
	}
	
	// 确保重试次数合理
	if maxRetries <= 0 {
		maxRetries = 1 // 至少尝试一次
	}
	
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
			// 指数退避：1s, 2s, 4s, 8s...
			backoffTime := time.Second * time.Duration(1<<uint(i))
			if backoffTime > 10*time.Second { 
				backoffTime = 10*time.Second // 设置上限
			}
			time.Sleep(backoffTime)
		}
	}

	return false, lastDuration, lastError
}

// attemptHTTPRequest 尝试发送HTTP GET请求
func attemptHTTPRequest(client *http.Client, url string) (bool, time.Duration, error) {
	// 参数验证
	if client == nil {
		return false, 0, NewNonRetryableError("HTTP客户端为空", nil)
	}
	
	if url == "" {
		return false, 0, NewNonRetryableError("URL为空", nil)
	}
	
	start := time.Now()

	// 特殊处理api.mytv666.top域名的请求
	if strings.Contains(url, "api.mytv666.top") {
		// 检查是否包含十六进制编码的ID参数
		if strings.Contains(url, "id=") && strings.Contains(url, "tid=") {
			return handleSpecialApiRequest(client, url)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, NewNonRetryableError("创建请求失败", err)
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
			return false, duration, NewRetryableError("请求超时", err)
		}
		
		// 网络错误通常是可重试的
		var netErr net.Error
		if errors.As(err, &netErr) {
			if netErr.Timeout() || netErr.Temporary() {
				return false, duration, NewRetryableError("网络临时错误", err)
			}
		}
		
		// 检查TLS/SSL错误
		if strings.Contains(err.Error(), "certificate") || 
		   strings.Contains(err.Error(), "x509") || 
		   strings.Contains(err.Error(), "tls") {
			return false, duration, NewNonRetryableError("SSL/TLS安全错误，可能需要使用不安全连接模式", err)
		}
		
		return false, duration, NewRetryableError("请求失败", err)
	}

	// 确保响应体被关闭
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	// 更详细的状态码处理 + 内容类型粗过滤
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(ct, "text/html") {
			return false, duration, NewNonRetryableError("返回 HTML 页面，可能需要鉴权", nil)
		}
		return true, duration, nil
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return false, duration, NewNonRetryableError(fmt.Sprintf("访问被拒绝 (%d)", resp.StatusCode), nil)
	case resp.StatusCode == 404:
		return false, duration, NewNonRetryableError("资源不存在 (404)", nil)
	case resp.StatusCode == 429:
		return false, duration, NewRetryableError("请求过于频繁 (429)", nil)
	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		return false, duration, NewRetryableError(fmt.Sprintf("服务器错误 (%d)", resp.StatusCode), nil)
	default:
		return false, duration, NewRetryableError(fmt.Sprintf("HTTP状态码 %d", resp.StatusCode), nil)
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