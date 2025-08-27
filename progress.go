package main

import (
	"fmt"
	"os"
)

// Increment 增加进度计数
func (p *Progress) Increment() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.Processed++

	if p.logLevel >= LogLevelNormal {
		updateFrequency := 1 // 默认每个任务都更新
		if p.Total > 100 {
			updateFrequency = 5
		}

		// 确保第一个、最后一个任务和每个updateFrequency任务都显示进度
		if p.Processed%updateFrequency == 0 || p.Processed == 1 || p.Processed == p.Total {
			percentage := float64(p.Processed*100) / float64(p.Total)
			// 使用 \r 回车符实现单行刷新
			fmt.Fprintf(os.Stderr, "Progress: %d/%d %.2f%% (Available: %d)   \r", p.Processed, p.Total, percentage, p.Available)

			// 当所有任务完成后，打印一个换行符，这样后续的输出就不会覆盖进度条
			if p.Processed == p.Total {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "Completed!")
			}
		}
	}
}

// UpdateAvailable 增加可用计数
func (p *Progress) UpdateAvailable() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.Available++
}
