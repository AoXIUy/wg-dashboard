# 🚀 WG-Monitor (WireGuard 极速监控面板)

**WG-Monitor** 是一个轻量级、零依赖的 WireGuard 流量监控面板。

它采用 Go 语言编写（后端）与 Vue.js 3（前端），专为 **嵌入式设备（如树莓派、RK3399、路由器）** 和 **Linux 服务器** 设计。得益于纯 Go 实现（Pure Go SQLite），它无需 GCC 即可在任何平台上极速编译运行。

## ✨ 核心特性

* **⚡️ 极轻量级**：单二进制文件，无任何系统依赖（无需 Python/PHP/Node.js）。
* **🚀 国内加速**：前端资源使用 Staticfile CDN，国内环境秒开，无白屏困扰。
* **📊 实时监控**：毫秒级采集，实时展示对等端（Peer）的上传/下载速率。
* **📈 历史图表**：内置 SQLite 数据库，支持查看 24小时 / 7天 / 30天 的流量趋势图。
* **🏷 别名管理**：支持点击前端 IP 直接修改别名（备注），无需修改配置文件。
* **🟢 智能状态**：基于 WireGuard 标准握手时间和流量增量的在线状态判定。
* **🛡 零 CGO**：使用纯 Go SQLite 驱动，跨平台（x86/ARM64）编译极其简单。

## 🛠 快速开始

### 1. 运行环境要求

* Linux 操作系统
* 已安装并配置好的 WireGuard 接口（默认 `wg0`）
* **Root 权限**（读取 WireGuard 内核数据需要）

### 2. 下载与运行 (编译版)

如果你不想自己编译，可以在本机编译好上传，或者直接在服务器上编译（推荐，因为很快）。

### 3. 从源码编译 (推荐)

由于移除了 CGO 依赖，编译速度极快（RK3399 上仅需几秒）。

```bash
# 1. 下载代码并整理依赖
go mod tidy

# 2. 编译 (禁用 CGO 以获得最佳兼容性)
CGO_ENABLED=0 go build -ldflags "-s -w" -o wg-monitor main.go

# 3. 运行
sudo ./wg-monitor

```

访问浏览器：`http://你的IP:8080`

## ⚙️ 命令行参数

程序支持通过命令行参数自定义配置：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-iface` | `wg0` | 要监控的 WireGuard 接口名称 |
| `-port` | `:8080` | Web 面板监听端口 |
| `-db` | `./wg_stats.db` | SQLite 数据库存储路径 |
| `-days` | `30` | 历史数据保留天数 (0 为永久) |

**示例：**

```bash
./wg-monitor -port :9090 -iface wg1 -db /data/wg.db

```

## 📦 生产环境部署 (Systemd)

为了实现开机自启和后台运行，建议使用 Systemd。

1. **安装文件**：
```bash
mkdir -p /var/lib/wg-monitor
cp wg-monitor /usr/local/bin/
chmod +x /usr/local/bin/wg-monitor

```


2. **创建服务文件** `/etc/systemd/system/wg-monitor.service`：
```ini
[Unit]
Description=WireGuard Monitor Dashboard
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/wg-monitor -iface wg0 -port :8080 -db /var/lib/wg-monitor/wg_stats.db
WorkingDirectory=/var/lib/wg-monitor
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target

```


3. **启动服务**：
```bash
systemctl daemon-reload
systemctl enable wg-monitor
systemctl start wg-monitor

```



## 📖 使用指南

### 修改别名

在 **列表监控** 页面，鼠标点击 Peer IP 上方的文字（默认为“无别名”），输入新名字后按回车即可保存。

### 查看历史详情

点击列表右侧的 **“历史详情”** 按钮，可以查看该用户最近 24小时、7天或 30天的流量使用情况和速率波形图。

### 在线状态说明

* **🟢 在线**：最近 3 分钟内有握手成功记录。
* **⚪️ 离线**：超过 3 分钟未握手。
* **速率 0 B/s**：表示当前设备在线但没有数据传输，属于正常现象。

## 🏗 技术栈

* **Backend**: Go (Golang)
* **Web Framework**: Gin
* **Database**: SQLite (modernc.org/sqlite - Pure Go)
* **WG Control**: wireguard/wgctrl
* **Frontend**: Vue.js 3, TailwindCSS, Chart.js (CDN)

## 🤝 贡献与协议

本项目开源，遵循 MIT 协议。欢迎提交 PR 或 Issue。

---

*Generated for WG-Monitor Optimized Version*