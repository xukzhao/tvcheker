package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

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
		if resp.Body != nil {
			resp.Body.Close()
		}
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
		if resp2.Body != nil {
			resp2.Body.Close()
		}
	}()

	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取URL时HTTP状态码为 %d", resp2.StatusCode)
	}

	return parseChannels(resp2.Body)
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
	tvgNameStart := strings.Index(extinfLine, `tvg-name=\""`)
	if tvgNameStart != -1 {
		tvgNameStart += len(`tvg-name=\""`)
		tvgNameEnd := strings.Index(extinfLine[tvgNameStart:], `\""`)
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
