# Go IPTV Checker

一个高效、智能的IPTV直播源检测工具。

## 描述

本项目是一个使用 Go 语言编写的命令行工具，用于并发检查IPTV直播源（.m3u8, .flv, etc.）的可用性。它支持从本地文件和网络URL加载直播源列表，并能生成可用的播放列表文件。

经过多次迭代，本工具内置了多种智能检测机制，能有效过滤广告、失效链接和无信号的“伪”直播源。

## 主要功能

- **高并发检测**：利用Go的并发特性，快速检查大量直播源。
- **可配置的检测引擎**：通过 `-ffprobe-mode` 参数，可自由选择检测策略：
    - `disable`: 只进行快速的一级检测，不使用ffprobe。
    - `only`: 只使用ffprobe进行深度检测。
    - `auto`: 自动模式，结合一级检测和ffprobe二级检测，实现最佳平衡。
- **智能校验**：
    - 不仅仅是检查网络连通性，更能深入分析M3U8播放列表。
    - 自动过滤VOD（点播）性质的短视频或广告。
    - 通过关键字匹配，屏蔽“无信号”等无效视频流。
- **动态并发**：
    - 实时监控系统CPU和内存负载。
    - 当系统负载过高时，自动降低并发数，避免电脑卡顿。
- **优雅停机**：通过 `Ctrl+C` 发出中断信号时，程序能迅速响应并安全退出。
- **多种输入源**：支持从本地文件（如 `tv.txt`）和网络URL加载直播源。
- **灵活输出**：
    - 生成详细的检测报告 `out.txt`。
    - 生成可直接使用的 `public/live.txt` 和 `public/live.m3u` 播放列表。
    - `live.m3u` 文件会根据 `groups.json` 的配置进行频道分组。

## FFprobe 深度检测

为了实现最精准的直播源内容验证，本工具支持调用 **FFmpeg** 套件中的 `ffprobe` 程序进行二级深度检测。

本工具通过 `-ffprobe-mode` 参数提供了灵活的二级检测策略。如果设置为 `auto` 或 `only` 模式，则需要您的系统上安装了 FFmpeg。

- **如果您的系统中未安装 FFmpeg**：请使用默认的 `disable` 模式（或将 `-ffprobe-mode` 设置为 `disable`），程序将正常运行，执行所有原生检测逻辑。
- **如果您的系统中已安装 FFmpeg**：您可以使用 `auto` 或 `only` 模式来启用 `ffprobe` 深度检测，能更有效地过滤掉无效和伪装的视频流，但检测速度会稍慢。

### 如何安装 FFmpeg?

**对于 Linux (Ubuntu/Debian):**
```bash
sudo apt update && sudo apt install ffmpeg
```

**对于 Linux (CentOS/RHEL):**
```bash
sudo yum install ffmpeg 
# 或者 sudo dnf install ffmpeg (可能需要EPEL/RPM Fusion源)
```

**对于 Windows:**
可以从官网 [ffmpeg.org](https://ffmpeg.org/download.html) 下载预编译好的文件，解压后，将 `bin` 目录的路径添加到系统的 `Path` 环境变量中。

安装完成后，可以在命令行中运行 `ffprobe -version` 来验证是否安装成功。

## 使用方法

基础用法：
```bash
main_win64.exe [参数]
```

例如，检查 `tv.txt` 文件中的直播源，使用20个并发，超时时间为15秒，并禁用ffprobe：
```bash
main_win64.exe -file tv.txt -concurrency 20 -timeout 15 -ffprobe-mode disable
```

## 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-file` | `tv.txt` | 本地电视频道文件路径。 |
| `-urls` | `""` | 获取电视频道的URL列表，用逗号分隔。 |
| `-urlfile` | `""` | 包含URL的文件路径，每行一个URL。 |
| `-groups` | `groups.json` | 自定义分组配置文件路径。 |
| `-concurrency`| `10` | 并发检查数。 |
| `-timeout` | `30` | 每个请求的超时时间（秒）。 |
| `-global-timeout`| `30` | 程序运行的总超时时间（分钟）。 |
| `-output` | `out.txt` | 详细检测结果的输出文件。 |
| `-retries` | `2` | 最大重试次数。 |
| `-loglevel` | `normal` | 日志级别: `silent`, `normal`, `verbose`。 |
| `-outdir` | `public` | 可用频道播放列表的输出目录。 |
| `-secure` | `false` | 是否验证SSL证书。设置为`true`可提高安全性，但可能导致某些自签名证书的站点无法访问。 |
| `-ffprobe-mode`| `auto` | FFprobe检测模式: `auto` (自动), `disable` (禁用), `only` (仅使用ffprobe)。 |

## 输出文件

- **`out.txt`**: 包含了所有直播源的详细检测结果，包括可用性、响应时间和错误信息。
- **`public/live.txt`**: 纯文本格式的可用直播源列表，格式为 `频道名称,URL`。
- **`public/live.m3u`**: M3U播放列表格式的可用直播源，支持按 `groups.json` 的规则进行分组，可直接用于VLC、PotPlayer等播放器。
