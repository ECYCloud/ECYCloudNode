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

流量按节点接收并准备转发的代理数据计量，转发前须完成账本提交；网络发送失败或部分发送时，已接收的数据仍计入，不以客户端确认收到的字节数为口径。面板移除官方设备会撤销其令牌，节点成功同步用户列表后拒绝旧凭据，已有连接的数据传输也执行授权检查。

Xray 的落盘计费接在实际出站转发路径，上行与下行均在交付前提交；内核内存统计只用于速率采样，不再作为待报账本。各协议的已有连接随用户同步应用当前限速，超出限速器单次容量的数据分段等待，等待失败停止转发，等待后复查授权。

## 编译

需要 Go 1.27.1+（见 `go.mod`）：

```bash
go build -tags with_quic -o ECYCloudNode .
./ECYCloudNode version
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
