# `ip_to_mac`

一个基于 Linux `netlink` 的 IP 到 MAC 解析工具，支持 IPv4 和 IPv6。

它的目标不是单纯“查 ARP 表”，而是尽量模拟“当前主机访问这个目标 IP 时，内核会走哪条路、出哪个接口、最终依赖哪个邻居项”，然后返回那条路径上的 MAC。

当前实现文件是 [ip_to_mac.cpp](/home/ryk/Documents/code/c/ip_to_mac.cpp)。

## 构建

```bash
g++ -std=c++17 -Wall -Wextra -pedantic ip_to_mac.cpp -o ip_to_mac
```

## 使用

```bash
./ip_to_mac <IPv4-or-IPv6>
```

示例：

```bash
./ip_to_mac 192.0.2.10
./ip_to_mac 2001:db8::10
```

输出示例：

```text
IP: 192.0.2.10
MAC: 00:11:22:33:44:55
Interface: eth0.100
Source: gateway-neighbor-cache
```

## 当前支持的场景

- 目标 IP 就是本机接口地址，直接返回该接口自身 MAC
- 目标 IP 已经在内核邻居缓存中，直接返回目标邻居 MAC
- 目标 IP 命中直连路由，按路由出口接口解析目标邻居 MAC
- 目标 IP 命中网关路由，按路由出口接口解析网关邻居 MAC
- 邻居缓存未命中时，发起一次轻量 UDP probe，触发内核进行 ARP 或 NDP，再回查邻居表
- IPv4 和 IPv6 共用同一套主流程
- 多源地址场景下，先尝试首选源地址，再枚举本机地址候选重试
- 默认主路由表没有命中，但策略路由能导向其他表的场景
- 多个子接口、VLAN 子接口、bond master 等由内核正常选路的场景
- 同一个网关 IP 出现在多个接口上时，按 `oif` 收敛到正确邻居项

## 典型适用场景

- HTTP 插件或其他出站请求插件，只知道目标 IP，不知道具体出口网卡
- 主机存在多张网卡、多业务 IP、多 VLAN 子接口
- 需要兼容 IPv4 和 IPv6
- 系统启用了策略路由，目标路径不一定落在主路由表
- 目标是直连主机，或者需要经过默认/非默认网关转发

## 不需要调用方传入的参数

调用方只需要传目标 IP。

不需要显式传入：

- 网卡名
- 接口索引
- 路由表 ID
- IPv4 / IPv6 类型标记

这些信息由程序通过 `getifaddrs`、`RTM_GETROUTE`、`RTM_GETNEIGH` 和一次 UDP 探测自动推导。

## 解析流程

整体入口在 [ip_to_mac.cpp](/home/ryk/Documents/code/c/ip_to_mac.cpp#L1134)。

按顺序执行：

1. 识别输入是 IPv4 还是 IPv6
2. 检查目标是否就是本机接口地址
3. 直接检查邻居缓存里是否已有目标 MAC
4. 用 UDP `connect()` 推导首选源地址
5. 带 `dst + src + oif` 查询路由
6. 命中直连路由时，按出口接口查目标邻居
7. 命中网关路由时，按出口接口查网关邻居
8. 邻居未命中时，发一个轻量 UDP probe 触发内核做 ARP/NDP，再回查
9. 如果首选源地址不足以命中路径，则枚举本机地址候选继续重试

## `Source` 字段含义

- `local-interface`: 目标 IP 就是本机接口地址
- `neighbor-cache`: 目标 IP 本身已在邻居缓存中
- `direct-route-neighbor-cache`: 目标 IP 命中直连路由，返回目标邻居 MAC
- `gateway-neighbor-cache`: 目标 IP 命中网关路由，返回网关邻居 MAC

## 当前边界

- 依赖 Linux 内核路由和邻居子系统，不适用于非 Linux 平台
- 主动探测使用的是轻量 UDP 发送，借内核触发 ARP/NDP；没有自己构造原始 ARP 或 ICMPv6 NS 报文
- 更复杂的策略路由上下文目前没有覆盖，例如依赖 `fwmark`、`iif`、`tos`、uid 或更复杂 socket 属性的规则
- IPv6 目标支持常规出站场景；特别复杂的 link-local 下一跳 / scope 相关场景没有专门增强

## 代码对应

- 邻居查询与过滤：[ip_to_mac.cpp](/home/ryk/Documents/code/c/ip_to_mac.cpp#L1015)
- 主动触发邻居解析：[ip_to_mac.cpp](/home/ryk/Documents/code/c/ip_to_mac.cpp#L566)
- 路由查询：[ip_to_mac.cpp](/home/ryk/Documents/code/c/ip_to_mac.cpp#L699)
- 路由回退查 MAC：[ip_to_mac.cpp](/home/ryk/Documents/code/c/ip_to_mac.cpp#L1077)
- 总入口：[ip_to_mac.cpp](/home/ryk/Documents/code/c/ip_to_mac.cpp#L1134)
