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

* 对接 SSPanel WebAPI（`PanelType: SSPanel`）
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
ECYCloudNode kernels      仅打印内嵌内核版本
ECYCloudNode uninstall    卸载
```

## 配置说明

示例见 [`release/config/config.yml.example`](./release/config/config.yml.example) 与 [`release/README.md`](./release/README.md)。

常用项：

* `Nodes[].PanelType`：固定为 `SSPanel`
* `Nodes[].ApiConfig.ApiHost` / `ApiKey` / `NodeID`：面板地址、MuKey、节点 ID
* `DnsConfigPath` / `RouteConfigPath` 等：可选；留空（注释）则不加载对应 JSON
* 证书：优先由面板 `ecycloudnode_cert` 下发；也可在节点侧自行配置 CertConfig

上游协议与 Xray 配置文档可参考：

* [XrayR 文档（上游）](https://xrayr-project.github.io/XrayR-doc/)
* [Xray-core 配置](https://xtls.github.io/)

## 编译

需要 Go 1.26+（见 `go.mod`）：

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
