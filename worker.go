package main

import (
	"context"
	"sync"
	"time"
)

// WorkerManager 工作线程管理器
type WorkerManager struct {
	Config  *Config
	Logger  *Logger
	Context context.Context
}

// NewWorkerManager 创建一个新的工作线程管理器
func NewWorkerManager(ctx context.Context, config *Config, logger *Logger) *WorkerManager {
	return &WorkerManager{
		Config:  config,
		Logger:  logger,
		Context: ctx,
	}
}

// ProcessChannels 处理频道列表，使用并发工作线程
func (wm *WorkerManager) ProcessChannels(channels []Channel) ([]Result, error) {
	if len(channels) == 0 {
		return nil, nil
	}

	// 创建通道
	jobs := make(chan Channel, len(channels))
	results := make(chan Result, len(channels))

	// 创建进度跟踪器
	progress := &Progress{
		Total:     len(channels),
		Processed: 0,
		logLevel:  wm.Logger.level,
	}

	// 启动工作线程
	var wg sync.WaitGroup
	timeout := time.Duration(wm.Config.Timeout) * time.Second

	// 根据配置的并发数启动工作线程
	for i := 0; i < wm.Config.Concurrency; i++ {
		wg.Add(1)
		go worker(wm.Context, &wg, jobs, results, timeout, wm.Config.MaxRetries, progress, wm.Config, wm.Logger)
	}

	// 发送任务到工作线程
	for _, channel := range channels {
		select {
		case <-wm.Context.Done():
			close(jobs) // 关闭任务通道
			return nil, wm.Context.Err()
		case jobs <- channel:
			// 任务已发送
		}
	}

	// 关闭任务通道，表示没有更多任务
	close(jobs)

	// 创建一个通道来接收结果收集完成的信号
	done := make(chan struct{})

	// 收集结果
	allResults := make([]Result, 0, len(channels))
	go func() {
		for result := range results {
			allResults = append(allResults, result)

			// 更新进度
			progress.Increment()

			// 如果结果可用，更新可用计数
			if result.Available {
				progress.UpdateAvailable()
			}
		}
		close(done)
	}()

	// 等待所有工作线程完成
	wg.Wait()

	// 关闭结果通道
	close(results)

	// 等待结果收集完成
	<-done

	return allResults, nil
}

// worker 工作线程，处理频道检查任务
func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan Channel, results chan<- Result, timeout time.Duration, maxRetries int, _ *Progress, config *Config, logger *Logger) {
	defer wg.Done()
	client := createHTTPClient(config.SecureConnect, int(timeout.Seconds()), logger)

	for {
		select {
		case <-ctx.Done(): // 检查上下文是否已取消
			return
		case channel, ok := <-jobs:
			if !ok {
				return // 通道已关闭
			}
			// 收到任务，执行检查
			available, responseTime, err := checkChannel(client, channel, maxRetries, config, logger)

			// 在发送结果前再次检查上下文，避免在处理期间收到取消信号
			select {
			case <-ctx.Done():
				return
			case results <- Result{
				Channel:      channel,
				Available:    available,
				ResponseTime: responseTime,
				Error:        err,
			}:
			}
		}
	}
}
