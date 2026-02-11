# ⚡ WireGuard Pro Dashboard (Enterprise Edition)

[![Go Version](https://img.shields.io/github/go-mod/go-version/yourusername/wg-dashboard?style=flat-square)](https://golang.org/doc/devel/release.html)
![License](https://img.shields.io/badge/License-GPLv3-blue.svg)
[![Vue 3](https://img.shields.io/badge/Frontend-Vue.js%203-4FC08D?style=flat-square&logo=vue.js)](https://vuejs.org/)
[![Tailwind](https://img.shields.io/badge/Style-Tailwind%20CSS-38B2AC?style=flat-square&logo=tailwind-css)](https://tailwindcss.com/)
[![MySQL](https://img.shields.io/badge/Database-MySQL-4479A1?style=flat-square&logo=mysql)](https://www.mysql.com/)
[![Redis](https://img.shields.io/badge/Cache-Redis-DC382D?style=flat-square&logo=redis)](https://redis.io/)

**企业级 · 高性能 · 实时可视化的 WireGuard 管理平台**

[特性介绍](#-核心特性) • [架构升级](#-架构升级) • [快速部署](#-快速部署) • [配置参数](#-配置参数)

---

![Dashboard Preview](docs/screenshot_main.png)
*(注：请确保 `docs/` 目录下有对应截图)*

> [!IMPORTANT]
> **架构变更通知**: 本项目已从单机 SQLite 架构升级为 **MySQL + Redis** 分布式架构，以支持海量数据存储与高并发实时推送。这是重大不兼容更新。

## 📖 简介

**WireGuard Pro Dashboard** 是一个基于 **Go (Gin)** 和 **Vue.js 3** 构建的高性能 WireGuard 管理系统。

与传统轻量版不同，Pro 版引入了 **MySQL** 用于持久化海量流量日志，使用 **Redis** 实现 Pub/Sub 实时消息广播与高性能缓存。它专为需要长期监控、地理位置追踪和深度流量分析的场景设计。

## ✨ 核心特性

### ⚡ 极致性能 (Enterprise Architecture)
* **实时推送**: 基于 **Redis Pub/Sub + SSE (Server-Sent Events)** 实现毫秒级流量更新，拒绝轮询延迟。
* **高并发支持**: Redis 缓存层大幅降低数据库压力，支持多实例水平扩展。
* **海量日志**: 依托 MySQL 存储，轻松回溯数月甚至数年的流量历史。

### 🌍 地图拓扑与地理位置 (New!)
* **全球可视化**: 自动解析 Peer IP 归属地，并在交互式地图上展示连接拓扑。
* **多源定位**: 集成 GeoLite2 本地库 + 在线 API (ip-api.com) + Redis 缓存，确保定位精准且高效。
* **智能解析**: 自动识别 ASN (运营商) 与城市信息。

### 📊 深度分析 (Advanced Analytics)
* **健康度评分**: 基于在线时长、丢包率 (Ping RTT) 与流量特征，综合计算客户端健康分。
* **行为画像**: 24小时活跃时段热力图，识别用户使用习惯。
* **流量审计**: 详细记录所有连接的 IP 变动与流量消耗。

### 🛠 全能管理
* **客户端管理**: 一键创建/删除/禁用 Peer，支持生成二维码与配置文件下载。
* **IP 自动分配**: 智能扫描网段，自动推荐可用 IP，避免冲突。
* **即时生效**: 通过 `wg-quick` 与 `wg syncconf` 实现配置热加载，无需重启接口。

## 🛠 技术栈

| 模块 | 技术选型 | 说明 |
| :--- | :--- | :--- |
| **Backend** | **Go (Gin)** | 高性能 API 网关, 协程并发处理 |
| **Database** | **MySQL 5.7/8.0** | 核心业务数据与流量日志存储 |
| **Cache/PubSub** | **Redis** | 实时状态缓存, SSE 消息广播队列 |
| **Frontend** | **Vue.js 3** | Composition API, 响应式单页应用 |
| **Styling** | **Tailwind CSS** | 现代化 UI 设计 |
| **GeoIP** | **GeoLite2** | MaxMind 离线数据库 (City & ASN) |

## 🚀 快速部署

### 1. 环境准备

确保服务器已安装以下组件：
* **WireGuard 内核模块**: (`wg`, `wg-quick` 命令可用)
* **MySQL**: 创建数据库 `wg_monitor` (编码 `utf8mb4`)
* **Redis**: 准备连接地址 (如 `127.0.0.1:6379`)
* **GeoLite2 数据库**: 下载 `GeoLite2-City.mmdb` 和 `GeoLite2-ASN.mmdb` 放置于运行目录。

### 2. 编译安装

```bash
# 1. 克隆代码
git clone https://github.com/yourusername/wg-dashboard.git
cd wg-dashboard

# 2. 编译
go build -o wg-dashboard main.go funcs.go analysis.go
# (注: 如果文件拆分了，请确保编译包含所有 .go 文件)

# 3. 运行 (需 root 权限操作 wg 接口)
sudo ./wg-dashboard \
  -mysql "user:pass@tcp(127.0.0.1:3306)/wg_monitor?charset=utf8mb4&parseTime=True&loc=Local" \
  -redis "127.0.0.1:6379" \
  -iface wg0
```

### 3. Docker Compose (推荐)

```yaml
version: '3'
services:
  dashboard:
    image: wg-dashboard:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
    volumes:
      - /etc/wireguard:/etc/wireguard
      - ./GeoLite2-City.mmdb:/app/GeoLite2-City.mmdb
    command: >
      ./wg-dashboard 
      -mysql "root:root@tcp(127.0.0.1:3306)/wg_monitor..."
      -redis "127.0.0.1:6379"
```

## ⚙️ 配置参数

支持通过命令行参数深度定制：

| 参数 | 默认值 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `-mysql` | `wg_user:cloud123@...` | **是** | MySQL 连接字符串 (DSN) |
| `-redis` | `192.168.10.119:6379` | **是** | Redis 服务器地址 |
| `-iface` | `wg0` | 否 | 监控的 WireGuard 接口名称 |
| `-port` | `:8080` | 否 | Web 服务监听端口 |
| `-password` | `admin123` | 否 | **(务必修改)** 管理员登录密码 |
| `-secret` | `change_...` | 否 | JWT 签名密钥 (用于 API 安全) |
| `-geo-city` | `./GeoLite2-City.mmdb` | 否 | GeoIP 城市库路径 |
| `-geo-asn` | `./GeoLite2-ASN.mmdb` | 否 | GeoIP ASN 库路径 |
| `-days` | `30` | 否 | 历史分析数据的默认查询窗口 (天) |

## 🔄 升级指南 (SQLite -> MySQL)

由于底层存储引擎变更，旧版 `wg_stats.db` (SQLite) 数据**无法直接兼容**。
建议在部署新版前备份旧数据，新版将从零开始记录流量历史。

1. 停止旧服务。
2. 配置 MySQL 与 Redis 环境。
3. 启动新版 Dashboard，系统会自动初始化 MySQL 表结构 (`traffic_history`, `peer_aliases`)。

## 📂 项目结构

```text
.
├── main.go              # 程序入口, API 路由, 核心流程控制
├── funcs.go             # 辅助函数 (GeoIP, 管理操作, 工具类)
├── analysis.go          # (隐含) 深度分析引擎逻辑
├── index.html           # Vue3 前端资源 (Embed)
├── static/              # 静态资源 (JS/CSS/Img)
└── README.md            # 本文档
```

## 🤝 贡献与支持

欢迎提交 **Pull Request** 或 **Issue**！
如果项目对你有帮助，请给一个 ⭐️ **Star**！

## 📄 开源协议

基于 ![License](https://img.shields.io/badge/License-GPLv3-blue.svg) 开源。
