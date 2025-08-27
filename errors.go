package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ErrorType 定义错误类型
type ErrorType string

const (
	// ErrorTypeNetwork 网络错误
	ErrorTypeNetwork ErrorType = "network"
	// ErrorTypeHTTP HTTP错误
	ErrorTypeHTTP ErrorType = "http"
	// ErrorTypeTimeout 超时错误
	ErrorTypeTimeout ErrorType = "timeout"
	// ErrorTypeFormat 格式错误
	ErrorTypeFormat ErrorType = "format"
	// ErrorTypeValidation 验证错误
	ErrorTypeValidation ErrorType = "validation"
	// ErrorTypeFFprobe FFprobe错误
	ErrorTypeFFprobe ErrorType = "ffprobe"
	// ErrorTypeUnknown 未知错误
	ErrorTypeUnknown ErrorType = "unknown"
)

// ChannelError 表示频道检查过程中的错误
type ChannelError struct {
	URL       string    // 频道URL
	Retryable bool      // 是否可重试
	Cause     error     // 原始错误
	Type      ErrorType // 错误类型
	HTTPCode  int       // HTTP状态码（如果适用）
	Details   string    // 额外的错误详情
}

func (e *ChannelError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("频道错误 [%s] %s", e.Type, e.URL))

	if e.HTTPCode > 0 {
		sb.WriteString(fmt.Sprintf(", HTTP状态码: %d", e.HTTPCode))
	}

	if e.Details != "" {
		sb.WriteString(", " + e.Details)
	}

	if e.Cause != nil {
		sb.WriteString(": " + e.Cause.Error())
	}

	return sb.String()
}

func (e *ChannelError) Unwrap() error {
	return e.Cause
}

// NewChannelError 创建一个新的频道错误
func NewChannelError(url string, errType ErrorType, cause error, retryable bool) *ChannelError {
	return &ChannelError{
		URL:       url,
		Type:      errType,
		Cause:     cause,
		Retryable: retryable,
	}
}

// NewHTTPChannelError 创建一个HTTP错误
func NewHTTPChannelError(url string, statusCode int, cause error, retryable bool) *ChannelError {
	return &ChannelError{
		URL:       url,
		Type:      ErrorTypeHTTP,
		Cause:     cause,
		Retryable: retryable,
		HTTPCode:  statusCode,
	}
}

// NewNetworkChannelError 创建一个网络错误
func NewNetworkChannelError(url string, cause error) *ChannelError {
	return &ChannelError{
		URL:       url,
		Type:      ErrorTypeNetwork,
		Cause:     cause,
		Retryable: true, // 网络错误通常可重试
	}
}

// NewTimeoutChannelError 创建一个超时错误
func NewTimeoutChannelError(url string, cause error) *ChannelError {
	return &ChannelError{
		URL:       url,
		Type:      ErrorTypeTimeout,
		Cause:     cause,
		Retryable: true, // 超时错误通常可重试
	}
}

// NewValidationChannelError 创建一个验证错误
func NewValidationChannelError(url string, cause error) *ChannelError {
	return &ChannelError{
		URL:       url,
		Type:      ErrorTypeValidation,
		Cause:     cause,
		Retryable: false, // 验证错误通常不可重试
	}
}

// NewFFprobeChannelError 创建一个FFprobe错误
func NewFFprobeChannelError(url string, cause error) *ChannelError {
	return &ChannelError{
		URL:       url,
		Type:      ErrorTypeFFprobe,
		Cause:     cause,
		Retryable: false, // FFprobe错误通常不可重试
	}
}

// IsNetworkError 判断是否为网络错误
func IsNetworkError(err error) bool {
	var channelErr *ChannelError
	if errors.As(err, &channelErr) {
		return channelErr.Type == ErrorTypeNetwork
	}

	// 检查常见网络错误
	return errors.Is(err, http.ErrHandlerTimeout) ||
		errors.Is(err, http.ErrBodyNotAllowed) ||
		errors.Is(err, http.ErrBodyReadAfterClose) ||
		errors.Is(err, http.ErrContentLength) ||
		errors.Is(err, http.ErrMissingFile) ||
		errors.Is(err, http.ErrNotMultipart) ||
		errors.Is(err, http.ErrSkipAltProtocol) ||
		errors.Is(err, http.ErrUseLastResponse)
}

// IsTimeoutError 判断是否为超时错误
func IsTimeoutError(err error) bool {
	var channelErr *ChannelError
	if errors.As(err, &channelErr) {
		return channelErr.Type == ErrorTypeTimeout
	}

	// 检查是否为net.Error且Timeout()返回true
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// IsRetryableError 判断错误是否可重试
func IsRetryableError(err error) bool {
	var channelErr *ChannelError
	if errors.As(err, &channelErr) {
		return channelErr.Retryable
	}

	// 默认情况下，网络错误和超时错误可重试
	return IsNetworkError(err) || IsTimeoutError(err)
}

// GetErrorType 获取错误类型
func GetErrorType(err error) ErrorType {
	var channelErr *ChannelError
	if errors.As(err, &channelErr) {
		return channelErr.Type
	}

	if IsNetworkError(err) {
		return ErrorTypeNetwork
	}

	if IsTimeoutError(err) {
		return ErrorTypeTimeout
	}

	return ErrorTypeUnknown
}
