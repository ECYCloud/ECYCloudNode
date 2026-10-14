# ECYCloudNode

![](https://img.shields.io/github/stars/ECYCloud/ECYCloudNode)
![](https://img.shields.io/github/forks/ECYCloud/ECYCloudNode)
![](https://github.com/ECYCloud/ECYCloudNode/actions/workflows/release.yml/badge.svg)
[![Github All Releases](https://img.shields.io/github/downloads/ECYCloud/ECYCloudNode/total.svg)]()

ECY Cloud 节点后端。基于 [XrayR](https://github.com/XrayR-project/XrayR) fork，面向 [SSPanel](https://github.com/Anankke/SSPanel-Uim)（本站面板）对接。

内嵌内核：

| 内核 | 用途 |
|------|------|
| [Xray-core](https://github.com/XTLS/Xray-core) | VLESS / VMess / Trojan / Shadowsocks |
| [sing-box](https://github.com/SagerNet/sing-box) | AnyTLS / TUIC 等 |
| [Hysteria2](https://github.com/apernet/hysteria) | Hysteria2 |

## 免责声明

本项目仅供学习与自用运维，不对可用性作任何保证，也不对使用本软件造成的任何后果负责。

## 特点

* 对接 SSPanel WebAPI
* 单进程可挂载多个节点 ID（`NodeID: 41,42,43`）
* 支持协议：VLESS、VMess、Trojan、Shadowsocks、Hysteria2、AnyTLS、TUIC
* 在线设备限制、节点/用户限速、审计规则、流量与节点状态上报
* 证书配置可由面板下发（`ecycloudnode_cert`）；亦支持节点侧 ACME（lego）
* 配置变更后按节点热更新；管理脚本提供安装、启停、更新与内核版本查看

## 安装路径

| 用途 | 路径 |
|------|------|
| 程序 | `/usr/local/ECYCloudNode/ECYCloudNode` |
| 配置与资源 | `/etc/ECYCloudNode/` |
| systemd | `ECYCloudNode.service` |
| 管理命令 | `ECYCloudNode`（亦可 `ecycloudnode`） |

## 一键安装

安装脚本与 unit 位于本仓库 [`release/`](./release/) 目录：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ECYCloud/ECYCloudNode/main/release/install.sh)
```

或：

```bash
wget -N https://raw.githubusercontent.com/ECYCloud/ECYCloudNode/main/release/install.sh && bash install.sh
```

指定版本：

```bash
bash install.sh vX.Y.Z
```

首次安装后编辑 `/etc/ECYCloudNode/config.yml`（至少配置 `ApiHost`、`ApiKey`、`NodeID`），然后：

```bash
systemctl enable --now ECYCloudNode
```

若由本站面板 SSH 一键部署，面板会写入上述配置并启动服务。

## 管理命令

```text
ECYCloudNode              显示管理菜单
ECYCloudNode start        启动
ECYCloudNode stop         停止
ECYCloudNode restart      重启
ECYCloudNode status       状态
ECYCloudNode enable       开机自启
ECYCloudNode disable      取消开机自启
ECYCloudNode log          查看日志（journald）
ECYCloudNode update       更新到最新 Release
ECYCloudNode update x.y.z 更新到指定版本
ECYCloudNode config       查看配置文件
ECYCloudNode version      版本与内嵌内核版本
ECYCloudNode uninstall    卸载
```

## 配置说明

示例见 [`release/config/config.yml.example`](./release/config/config.yml.example) 与 [`release/README.md`](./release/README.md)。

常用项：

* `Nodes[].ApiConfig.ApiHost` / `ApiKey` / `NodeID`：面板地址、MuKey、节点 ID
* `Nodes[].ApiConfig.TrafficDir`：可选的流量账本目录；默认 Linux 为 `/var/lib/ECYCloudNode/traffic`，Windows 为可执行文件旁的 `traffic`。目录须可写且持久化，容器必须挂载持久卷，升级时不要删除；不同面板地址与节点 ID 使用独立账本。更换面板地址、节点 ID 或目录前，先完成旧账本上报或迁移。
* `DnsConfigPath` / `RouteConfigPath` 等：可选；留空（注释）则不加载对应 JSON
* 证书：优先由面板 `ecycloudnode_cert` 下发；也可在节点侧自行配置 CertConfig

启用流量上报时，流量回调同步写入账本；提交期间到达的并发记录合并到后续事务，每个回调均等待磁盘提交成功，不设固定等待窗口。上报使用已持久化的固定报告编号；面板确认后仅移除该报告包含的计数。上报失败、进程重启、用户移除后仍保留待报流量。启动前通过节点信息接口核对上报协议，面板未声明 `traffic_report_version: 1` 时停止启动；禁止在新版节点运行期间将面板独立回退到不支持去重的版本。账本打不开时节点启动失败，写入失败时相关连接停止，不能回退为只在内存记账。节点连接权限仍来自面板用户列表及其到期时间。

流量按节点接收并准备转发的代理数据计量，转发前须完成账本提交；网络发送失败或部分发送时，已接收的数据仍计入，不以客户端确认收到的字节数为口径。踢官方设备下线会清理在线记录并通知客户端断开，保留登录凭据，之后可重新连接。账户禁用、到期或登录凭据失效时，节点按同步的用户列表和授权截止时间检查新连接及已有连接的数据传输。

Xray 的落盘计费接在实际出站转发路径，上行与下行均在交付前提交；内核内存统计只用于速率采样，不再作为待报账本。各协议的已有连接随用户同步应用当前限速，超出限速器单次容量的数据分段等待，等待失败停止转发，等待后复查授权。

## 编译

需要 Go 1.27.2+（见 `go.mod`）：

```bash
go run ./tools/prepare-xray.go /tmp/ecycloud-node-build
go build -modfile=/tmp/ecycloud-node-build/go.mod -tags with_quic -o ECYCloudNode .
./ECYCloudNode version
```

准备工具仅对 Xray `v1.260327.0` 且源码哈希匹配的版本应用既有 TLS 补丁。其他 Xray 版本自动停用旧补丁，使用 `go.mod` 指定的官方模块，并删除内容哈希匹配的 `patches/xray-tls-config.patch`；复用构建目录时也不会沿用旧内核替换。补丁已不存在时可重复运行，内容已改动或读取、删除失败时停止并报错。其他补丁、准备工具及旧源码副本不自动删除。

版本变化不代表上游已修复 OCSP，升级后须在未打补丁的内核上通过本地 OCSP 和完整回归；回退绑定版本前须恢复已验证的补丁文件。官方模块缓存和项目 `go.mod` / `go.sum` 保持原样。

Windows 本机使用 `D:\tmp\ecycloud-node-build`；交叉编译时先按宿主平台运行准备工具，再设置目标 `GOOS` / `GOARCH`。本地回归使用相同的 `-modfile`：

```bash
go test -modfile=/tmp/ecycloud-node-build/go.mod -tags with_quic -count=1 ./...
```

Release 构建见 [`.github/workflows/release.yml`](./.github/workflows/release.yml)。

## 致谢

* [XrayR](https://github.com/XrayR-project/XrayR) / [XrayR-project](https://github.com/XrayR-project)
* [Project X / Xray-core](https://github.com/XTLS/Xray-core)
* [sing-box](https://github.com/SagerNet/sing-box)
* [Hysteria](https://github.com/apernet/hysteria)
* [V2Fly](https://github.com/v2fly)

## 许可证

[Mozilla Public License Version 2.0](./LICENSE)
