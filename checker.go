package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// FFprobeStream 代表ffprobe JSON输出中单个流的结构
type FFprobeStream struct {
	CodecType string `json:"codec_type"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
}

// FFprobeOutput 代表ffprobe JSON输出的顶层结构
type FFprobeOutput struct {
	Streams []FFprobeStream `json:"streams"`
}

var ffprobeChecked = false
var ffprobePath = ""

// isFFprobeAvailable 检查ffprobe是否在系统中可用
func isFFprobeAvailable() bool {
	if !ffprobeChecked {
		path, err := exec.LookPath("ffprobe")
		if err == nil {
			ffprobePath = path
		}
		ffprobeChecked = true
	}
	return ffprobePath != ""
}

// getBufferSize 根据内容类型动态调整缓冲区大小
func getBufferSize(contentType string) int {
	if strings.Contains(contentType, "video") {
		return 4096 // 视频流需要更大缓冲区
	}
	return 1024
}

// checkChannel 是检查频道的总控制器
func checkChannel(client *http.Client, channel Channel, maxRetries int, config *Config, logger *Logger) (bool, time.Duration, error) {
	if client == nil {
		return false, 0, NewValidationChannelError(channel.URL, errors.New("HTTP客户端为空"))
	}
	if channel.URL == "" {
		return false, 0, NewValidationChannelError(channel.URL, errors.New("频道URL为空"))
	}
	if !isValidURL(channel.URL) {
		return false, 0, NewValidationChannelError(channel.URL, errors.New("无效的URL"))
	}

	mode := strings.ToLower(config.FFprobeMode)
	if mode == "" {
		mode = "auto"
	}

	runPrimary := mode == "auto" || mode == "disable"
	runSecondary := mode == "auto" || mode == "only"

	// --- 仅FFprobe模式 ---
	if mode == "only" {
		if !isFFprobeAvailable() {
			return false, 0, NewFFprobeChannelError(channel.URL, errors.New("ffprobe 'only' 模式已启用，但未找到ffprobe程序"))
		}
		logger.Debug("模式 'only': 跳过一级检测，直接使用 FFprobe: %s", channel.URL)
		ffprobeTimeout := 15 * time.Second
		valid, err := checkStreamWithFFprobe(channel.URL, ffprobeTimeout)
		return valid, 0, err
	}

	// --- Auto 和 Disable 模式 ---
	// 步骤1: 执行一级检测 (HTTP/HTTPS)
	var tier1Available bool
	var duration time.Duration
	var err error

	u, parseErr := url.Parse(channel.URL)
	if parseErr != nil {
		return false, 0, NewValidationChannelError(channel.URL, fmt.Errorf("解析URL失败: %v", parseErr))
	}

	if runPrimary {
		switch u.Scheme {
		case "http", "https":
			tier1Available, duration, err = checkHTTPStream(client, channel.URL, maxRetries)
		case "rtmp", "rtsp", "mms", "udp", "rtp":
			// 对于非HTTP协议，一级检测默认通过（因为没有可用的原生检测方法）
			tier1Available = true
			err = nil
			logger.Debug("协议 %s, 一级检测跳过: %s", u.Scheme, channel.URL)
		default:
			return false, 0, NewValidationChannelError(channel.URL, fmt.Errorf("不支持的协议: %s", u.Scheme))
		}
	}

	if !tier1Available {
		return false, duration, err // 一级检测失败，直接返回
	}

	// 步骤2: 根据需要执行二级FFprobe检测
	if runSecondary && isFFprobeAvailable() {
		logger.Debug("模式 'auto': 一级检测通过，开始 FFprobe 二级检测: %s", channel.URL)
		ffprobeTimeout := 10 * time.Second
		tier2Available, ffprobeErr := checkStreamWithFFprobe(channel.URL, ffprobeTimeout)
		if !tier2Available {
			return false, duration, ffprobeErr // 二级检测失败
		}
	} else if runSecondary && !isFFprobeAvailable() {
		logger.Warn("FFprobe 在 'auto' 模式下需要，但未找到。仅基于一级检测结果。\n")
	}

	// 如果执行到这里，说明所有需要的检测都已通过
	return true, duration, nil
}

// createHTTPClient 创建HTTP客户端
func createHTTPClient(secureConnect bool, timeout int, _ *Logger) *http.Client {
	transport := &http.Transport{
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !secureConnect,
		},
	}
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}
}

// checkStreamWithFFprobe 使用ffprobe进行二级深度检测
func checkStreamWithFFprobe(streamURL string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ffprobe",
		"-v", "quiet",
		"-print_format", "json",
		"-show_streams",
		"-select_streams", "v:0", // 只选择第一个视频流
		streamURL,
	)

	output, err := cmd.Output()
	if err != nil {
		return false, NewFFprobeChannelError(streamURL, fmt.Errorf("ffprobe执行失败: %w", err))
	}

	if len(output) == 0 {
		return false, NewFFprobeChannelError(streamURL, errors.New("ffprobe输出为空，可能不是有效的视频流"))
	}

	var ffprobeData FFprobeOutput
	if err := json.Unmarshal(output, &ffprobeData); err != nil {
		return false, NewFFprobeChannelError(streamURL, fmt.Errorf("解析ffprobe JSON输出失败: %w", err))
	}

	if len(ffprobeData.Streams) == 0 {
		return false, NewFFprobeChannelError(streamURL, errors.New("ffprobe未找到视频流"))
	}

	if ffprobeData.Streams[0].CodecType == "video" && ffprobeData.Streams[0].Width > 0 {
		return true, nil
	}

	return false, NewFFprobeChannelError(streamURL, errors.New("未找到有效的视频流信息"))
}

// checkHTTPStream 检查HTTP/HTTPS流是否可用 (仅一级检测)
func checkHTTPStream(client *http.Client, url string, maxRetries int) (bool, time.Duration, error) {
	if client == nil {
		return false, 0, NewValidationChannelError(url, errors.New("HTTP客户端为空"))
	}
	if url == "" {
		return false, 0, NewValidationChannelError(url, errors.New("URL为空"))
	}

	if maxRetries <= 0 {
		maxRetries = 1
	}

	var lastError error
	var lastDuration time.Duration

	for i := 0; i < maxRetries; i++ {
		available, duration, err := attemptHTTPRequest(client, url)
		lastDuration = duration

		if available {
			return true, duration, nil // 一级检测通过
		}

		lastError = err
		var channelErr *ChannelError
		if errors.As(err, &channelErr) {
			if !channelErr.Retryable {
				return false, duration, err // 不可重试错误，立即返回
			}
		} else if err != nil {
			return false, duration, err // 其他未知错误，不重试
		}

		if i < maxRetries-1 {
			backoffTime := time.Second * time.Duration(1<<uint(i))
			if backoffTime > 10*time.Second {
				backoffTime = 10 * time.Second
			}
			time.Sleep(backoffTime)
		}
	}

	return false, lastDuration, lastError
}

// attemptHTTPRequest 尝试发送HTTP GET请求 (一级检测的核心)
func attemptHTTPRequest(client *http.Client, urlVal string) (bool, time.Duration, error) {
	start := time.Now()

	if strings.Contains(urlVal, "api.mytv666.top") {
		if strings.Contains(urlVal, "id=") && strings.Contains(urlVal, "tid=") {
			return handleSpecialApiRequest(urlVal)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", urlVal, nil)
	if err != nil {
		return false, 0, NewValidationChannelError(urlVal, fmt.Errorf("创建请求失败: %w", err))
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return false, duration, NewTimeoutChannelError(urlVal, err)
		}
		var netErr net.Error
		if errors.As(err, &netErr) {
			if netErr.Timeout() {
				return false, duration, NewTimeoutChannelError(urlVal, err)
			} else if netErr.Temporary() {
				return false, duration, NewNetworkChannelError(urlVal, err)
			}
		}
		return false, duration, NewNetworkChannelError(urlVal, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(ct, "text/html") {
			return false, duration, NewHTTPChannelError(urlVal, resp.StatusCode, fmt.Errorf("返回 HTML 页面，可能需要鉴权"), false)
		}

		isM3U8 := strings.HasSuffix(strings.ToLower(urlVal), ".m3u8") || strings.Contains(ct, "application/vnd.apple.mpegurl") || strings.Contains(ct, "application/x-mpegurl")

		if isM3U8 {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return false, duration, NewChannelError(urlVal, ErrorTypeFormat, fmt.Errorf("读取M3U8内容失败: %w", err), true)
			}
			playlist := string(bodyBytes)

			if strings.Contains(playlist, "#EXT-X-ENDLIST") {
				return false, duration, NewChannelError(urlVal, ErrorTypeFormat, errors.New("M3U8是VOD (包含ENDLIST)，可能为广告"), false)
			}
			segmentCount := strings.Count(playlist, "#EXTINF:")
			if segmentCount > 0 && segmentCount < 2 {
				return false, duration, NewChannelError(urlVal, ErrorTypeFormat, fmt.Errorf("M3U8播放列表分片过少 (%d)，可能为广告", segmentCount), false)
			}
			if segmentCount == 0 && !strings.Contains(playlist, "#EXT-X-STREAM-INF") {
				return false, duration, NewChannelError(urlVal, ErrorTypeFormat, errors.New("M3U8播放列表无分片信息"), false)
			}

			// 检查播放列表长度
			lines := strings.Split(playlist, "\n")
			if len(lines) < 5 { // 简单的启发式检查
				return false, duration, NewChannelError(urlVal, ErrorTypeFormat, errors.New("M3U8播放列表过短，可能为无效流"), false)
			}

			blocklist := []string{"no_signal", "no-signal"}
			scanner := bufio.NewScanner(strings.NewReader(playlist))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasSuffix(line, ".ts") {
					for _, keyword := range blocklist {
						if strings.Contains(line, keyword) {
							return false, duration, NewChannelError(urlVal, ErrorTypeFormat, fmt.Errorf("M3U8分片URL包含屏蔽词 '%s'", keyword), false)
						}
					}
				}
			}
			return true, duration, nil
		} else {
			bufferSize := getBufferSize(ct)
			buffer := make([]byte, bufferSize)
			bytesRead, err := resp.Body.Read(buffer)
			if err != nil && err != io.EOF {
				return false, duration, &ChannelError{URL: urlVal, Retryable: true, Cause: fmt.Errorf("读取流内容时发生错误: %w", err)}
			}
			if err == io.EOF && bytesRead < 188 {
				return false, duration, &ChannelError{URL: urlVal, Retryable: false, Cause: fmt.Errorf("流内容过短 (%d bytes)，可能为广告或无效源", bytesRead)}
			}
			return true, duration, nil
		}
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return false, duration, &ChannelError{URL: urlVal, Retryable: false, Cause: fmt.Errorf("访问被拒绝 (%d): %s", resp.StatusCode, urlVal)}
	case resp.StatusCode == 404:
		return false, duration, &ChannelError{URL: urlVal, Retryable: false, Cause: fmt.Errorf("资源不存在 (%d)", resp.StatusCode)}
	case resp.StatusCode == 429:
		return false, duration, &ChannelError{URL: urlVal, Retryable: true, Cause: fmt.Errorf("请求过于频繁 (%d)", resp.StatusCode)}
	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		return false, duration, &ChannelError{URL: urlVal, Retryable: true, Cause: fmt.Errorf("服务器错误 (%d)", resp.StatusCode)}
	default:
		return false, duration, &ChannelError{URL: urlVal, Retryable: true, Cause: fmt.Errorf("HTTP状态码 %d", resp.StatusCode)}
	}
}

// handleSpecialApiRequest and its helpers are complex and contain a lot of printing.
// For now, we just make them return a non-retryable ChannelError.
func handleSpecialApiRequest(apiUrl string) (bool, time.Duration, error) {
	return false, 0, &ChannelError{URL: apiUrl, Retryable: false, Cause: errors.New("特殊API请求处理已禁用")}
}
