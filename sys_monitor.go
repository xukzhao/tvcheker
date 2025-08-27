package main

import (
	"runtime"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

// 全局系统监控器
var sysMonitor = &SystemMonitor{lastUpdate: time.Now()}

// Update 更新系统资源使用情况
func (sm *SystemMonitor) Update() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// 更新Goroutine数量
	sm.goroutineCount = runtime.NumGoroutine()

	// 更新内存使用率
	if v, err := mem.VirtualMemory(); err == nil {
		sm.memUsage = v.UsedPercent
	}

	// 更新CPU使用率
	if percentages, err := cpu.Percent(time.Second, false); err == nil && len(percentages) > 0 {
		sm.cpuUsage = percentages[0]
	}

	// 更新网络IO信息
	if ioStats, err := net.IOCounters(false); err == nil && len(ioStats) > 0 {
		sm.networkIO = ioStats[0]
	}

	sm.lastUpdate = time.Now()
}

// GetRecommendedConcurrency 获取建议的并发数
func (sm *SystemMonitor) GetRecommendedConcurrency(max int) int {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// 如果CPU或内存使用率过高，则降低并发数
	// 阈值可以根据需要调整
	if sm.cpuUsage > 80.0 || sm.memUsage > 80.0 {
		reducedConcurrency := max / 2
		if reducedConcurrency < 1 {
			return 1
		}
		return reducedConcurrency
	}

	// 如果goroutine数量过多，也适当降低并发
	// 这个阈值表示我们不希望有超过500个goroutine在运行
	if sm.goroutineCount > 500 {
		reducedConcurrency := max * 3 / 4
		if reducedConcurrency < 1 {
			return 1
		}
		return reducedConcurrency
	}

	// 默认情况下，使用用户指定的最大并发数
	return max
}
