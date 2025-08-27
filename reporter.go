package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

// processResults 处理检测结果通道 (保留用于兼容性，主要功能已迁移到processResultsList)
// nolint:unused

// processResultsList 处理检测结果列表
func processResultsList(ctx context.Context, results []Result, writer io.Writer, logLevel LogLevel) ([]Channel, *Stats, error) {
	var availableChannels []Channel
	stats := &Stats{}

	if logLevel >= LogLevelNormal {
		fmt.Fprintf(writer, "\n结果:\n")
	}

	// 按来源分离结果
	localResults := make([]Result, 0)
	networkResults := make([]Result, 0)

	// 处理结果
	for _, result := range results {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("操作被取消: %w", ctx.Err())
		default:
		}

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

	// 添加成功率统计
	totalLocal := stats.LocalAvailable + stats.LocalUnavailable
	if totalLocal > 0 {
		localSuccessRate := float64(stats.LocalAvailable) / float64(totalLocal) * 100
		fmt.Fprintf(writer, "本地频道成功率: %.2f%%\n", localSuccessRate)
	}

	totalNetwork := stats.NetworkAvailable + stats.NetworkUnavailable
	if totalNetwork > 0 {
		networkSuccessRate := float64(stats.NetworkAvailable) / float64(totalNetwork) * 100
		fmt.Fprintf(writer, "网络频道成功率: %.2f%%\n", networkSuccessRate)
	}

	total := totalLocal + totalNetwork
	if total > 0 {
		overallSuccessRate := float64(stats.LocalAvailable+stats.NetworkAvailable) / float64(total) * 100
		fmt.Fprintf(writer, "整体成功率: %.2f%%\n", overallSuccessRate)
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
