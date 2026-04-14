#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

enum Source {
    Local,
    Gateway,
    Neighbor,
    DirectRoute
};

struct MacLookupResult {
    std::string macAddress;
    std::string interfaceName;
    Source source;
};

struct RouteInfo {
    bool hasGateway = false;
    std::string gatewayIp;
    std::string interfaceName;
    int interfaceIndex = 0;
    std::uint32_t tableId = RT_TABLE_UNSPEC;
    int prefixLength = -1;
    std::uint32_t routePriority = UINT32_MAX;
};

struct ParsedRouteAttrs {
    bool hasGateway = false;
    bool hasOif = false;
    bool matchesTarget = false;
    in_addr v4{};
    in6_addr v6{};
    int oif = 0;
    std::uint32_t tableId = RT_TABLE_UNSPEC;
    std::uint32_t routePriority = UINT32_MAX;
};

struct RouteLookupOptions {
    std::uint32_t tableId = RT_TABLE_UNSPEC;
    bool hasSource = false;
    in_addr sourceV4{};
    in6_addr sourceV6{};
    int outputInterfaceIndex = 0;
};

struct LocalAddressCandidate {
    std::string interfaceName;
    int interfaceIndex = 0;
    in_addr v4{};
    in6_addr v6{};
};

constexpr std::size_t kNetlinkBufferSize = 32 * 1024;
constexpr int kNeighborProbeRetries = 3;
constexpr useconds_t kNeighborProbeRetryDelayUs = 200000;

bool Ipv4MatchesPrefix(const in_addr& ip, const in_addr& network, int prefixLength);
bool Ipv6MatchesPrefix(const in6_addr& ip, const in6_addr& network, int prefixLength);
std::optional<MacLookupResult> FindNeighborMac(int family,
                                               int expectedIfindex,
                                               const in_addr& v4,
                                               const in6_addr& v6);

std::size_t FamilyAddressSize(int family)
{
    if (family == AF_INET) {
        return sizeof(in_addr);
    }
    if (family == AF_INET6) {
        return sizeof(in6_addr);
    }
    return 0;
}

/**
 * @brief 将原始 MAC 字节数组格式化为十六进制字符串。
 * @param bytes MAC 地址字节数组首地址。
 * @param len MAC 地址字节长度。
 * @return 格式化后的 MAC 字符串。
 */
std::string FormatMac(const unsigned char* bytes, std::size_t len)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        if (i != 0) {
            oss << ':';
        }
        oss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return oss.str();
}

/**
 * @brief 判断一个 sockaddr 是否与目标 IP 完全一致。
 * @param addr 待比较的 sockaddr 指针。
 * @param family 目标地址族，支持 AF_INET 与 AF_INET6。
 * @param rawIp 目标 IP 的原始二进制地址。
 * @return 完全一致时返回 true，否则返回 false。
 */
bool SockaddrEqualsIp(const sockaddr* addr, int family, const void* rawIp)
{
    if (addr == nullptr || addr->sa_family != family) {
        return false;
    }

    if (family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(addr);
        return std::memcmp(&in->sin_addr, rawIp, sizeof(in_addr)) == 0;
    }

    if (family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        return std::memcmp(&in6->sin6_addr, rawIp, sizeof(in6_addr)) == 0;
    }

    return false;
}

/**
 * @brief 识别输入 IP 字符串的地址族并写入解析结果。
 * @param ip 输入的 IP 字符串。
 * @param v4 IPv4 解析结果输出参数。
 * @param v6 IPv6 解析结果输出参数。
 * @return 成功时返回 AF_INET 或 AF_INET6，失败时返回 AF_UNSPEC。
 */
int DetectFamily(const std::string& ip, in_addr* v4, in6_addr* v6)
{
    if (inet_pton(AF_INET, ip.c_str(), v4) == 1) {
        return AF_INET;
    }
    if (inet_pton(AF_INET6, ip.c_str(), v6) == 1) {
        return AF_INET6;
    }
    return AF_UNSPEC;
}

void PrintUsage(const char* argv0)
{
    std::cerr << "Usage: " << argv0 << " <IPv4-or-IPv6>\n";
}

/**
 * @brief 判断 IPv4 地址是否命中指定前缀。
 * @param ip 目标 IPv4 地址。
 * @param network 路由前缀地址。
 * @param prefixLength 前缀长度。
 * @return 命中时返回 true，否则返回 false。
 */
bool Ipv4MatchesPrefix(const in_addr& ip, const in_addr& network, int prefixLength)
{
    if (prefixLength < 0 || prefixLength > 32) {
        return false;
    }

    const std::uint32_t mask =
        (prefixLength == 0) ? 0U : (0xFFFFFFFFU << (32 - static_cast<unsigned int>(prefixLength)));
    const std::uint32_t ipValue = ntohl(ip.s_addr);
    const std::uint32_t netValue = ntohl(network.s_addr);
    return (ipValue & mask) == (netValue & mask);
}

/**
 * @brief 判断 IPv6 地址是否命中指定前缀。
 * @param ip 目标 IPv6 地址。
 * @param network 路由前缀地址。
 * @param prefixLength 前缀长度。
 * @return 命中时返回 true，否则返回 false。
 */
bool Ipv6MatchesPrefix(const in6_addr& ip, const in6_addr& network, int prefixLength)
{
    if (prefixLength < 0 || prefixLength > 128) {
        return false;
    }

    int bitsLeft = prefixLength;
    for (int i = 0; i < 16; ++i) {
        if (bitsLeft <= 0) {
            return true;
        }

        const int bitsThisByte = (bitsLeft >= 8) ? 8 : bitsLeft;
        const unsigned char mask = static_cast<unsigned char>(0xFFU << (8 - bitsThisByte));
        if ((ip.s6_addr[i] & mask) != (network.s6_addr[i] & mask)) {
            return false;
        }
        bitsLeft -= bitsThisByte;
    }

    return true;
}

class NetlinkSocket {
public:
    /**
     * @brief 创建一个用于访问 Linux 路由/邻居子系统的 netlink socket。
     */
    NetlinkSocket()
    {
        fd_ = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    }

    /**
     * @brief 销毁对象并关闭底层 netlink socket。
     */
    ~NetlinkSocket()
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    /**
     * @brief 获取底层 socket 描述符。
     * @return 底层 netlink socket fd。
     */
    int get() const
    {
        return fd_;
    }

private:
    int fd_ = -1;
};

class IfaddrsGuard {
public:
    /**
     * @brief 创建一个空的 ifaddrs 资源守卫。
     */
    IfaddrsGuard() = default;

    /**
     * @brief 在对象销毁时自动释放 ifaddrs 链表。
     */
    ~IfaddrsGuard()
    {
        if (ptr_ != nullptr) {
            ::freeifaddrs(ptr_);
        }
    }

    /**
     * @brief 返回底层 ifaddrs 指针地址，供 getifaddrs 填充。
     * @return ifaddrs 二级指针。
     */
    ifaddrs** out()
    {
        return &ptr_;
    }

    /**
     * @brief 返回底层 ifaddrs 链表首地址。
     * @return ifaddrs 一级指针。
     */
    ifaddrs* get() const
    {
        return ptr_;
    }

private:
    ifaddrs* ptr_ = nullptr;
};

/**
 * @brief 将来源枚举转换为可读字符串。
 * @param source 来源枚举值。
 * @return 对应的来源字符串。
 */
std::string SourceToString(Source source)
{
    switch (source) {
        case Source::Local:
            return "local-interface";
        case Source::Gateway:
            return "gateway-neighbor-cache";
        case Source::Neighbor:
            return "neighbor-cache";
        case Source::DirectRoute:
            return "direct-route-neighbor-cache";
    }
    return "unknown";
}

/**
 * @brief 从 netlink socket 读取一批消息到缓冲区。
 * @param sock netlink socket 封装对象。
 * @param buffer 接收消息的缓冲区。
 * @return 读取成功返回 true，失败返回 false。
 */
bool ReceiveNetlinkBuffer(NetlinkSocket& sock, std::vector<char>* buffer)
{
    bool retry = true;
    while (retry) {
        const ssize_t received = ::recv(sock.get(), buffer->data(), buffer->size(), 0);
        if (received >= 0) {
            buffer->resize(static_cast<std::size_t>(received));
            return true;
        }
        if (errno != EINTR) {
            return false;
        }
        // EINTR 表示 recv() 在完成前被信号中断，这种情况不是实际失败，应当直接重试。
        retry = (errno == EINTR);
    }
    return false;
}

/**
 * @brief 根据接口索引获取接口名，失败时返回 ifindex:<n> 形式的兜底字符串。
 * @param ifindex 接口索引。
 * @return 接口名字符串。
 */
std::string GetInterfaceName(int ifindex)
{
    char ifName[IF_NAMESIZE] = {};
    if (::if_indextoname(ifindex, ifName) != nullptr) {
        return ifName;
    }
    return "ifindex:" + std::to_string(ifindex);
}

/**
 * @brief 处理 RTA_GATEWAY，提取网关地址到统一的 v4/v6 字段。
 */
bool ParseRouteGatewayAttr(int family, const rtattr* attr, ParsedRouteAttrs* parsed)
{
    const auto addressSize = FamilyAddressSize(family);
    const auto payloadSize = static_cast<std::size_t>(RTA_PAYLOAD(attr));
    if (addressSize == 0 || payloadSize != addressSize) {
        return true;
    }

    if (family == AF_INET) {
        if (std::memcpy(&parsed->v4, RTA_DATA(attr), sizeof(parsed->v4)) != &parsed->v4) {
            std::cerr << "ParseRouteAttrs: memcpy v4 failed" << std::endl;
            return false;
        }
    } else if (family == AF_INET6) {
        if (std::memcpy(&parsed->v6, RTA_DATA(attr), sizeof(parsed->v6)) != &parsed->v6) {
            std::cerr << "ParseRouteAttrs: memcpy v6 failed" << std::endl;
            return false;
        }
    }

    parsed->hasGateway = true;
    return true;
}

/**
 * @brief 处理 RTA_OIF，提取路由出接口索引。
 */
bool ParseRouteOifAttr(const rtattr* attr, ParsedRouteAttrs* parsed)
{
    if (RTA_PAYLOAD(attr) != static_cast<int>(sizeof(parsed->oif))) {
        return true;
    }

    if (std::memcpy(&parsed->oif, RTA_DATA(attr), sizeof(parsed->oif)) != &parsed->oif) {
        std::cerr << "ParseRouteAttrs: memcpy oif failed" << std::endl;
        return false;
    }

    parsed->hasOif = true;
    return true;
}

/**
 * @brief 处理 RTA_PRIORITY，提取路由优先级供候选路由比较使用。
 */
bool ParseRoutePriorityAttr(const rtattr* attr, ParsedRouteAttrs* parsed)
{
    if (RTA_PAYLOAD(attr) != static_cast<int>(sizeof(parsed->routePriority))) {
        return true;
    }

    if (std::memcpy(&parsed->routePriority,
                    RTA_DATA(attr),
                    sizeof(parsed->routePriority)) != &parsed->routePriority) {
        std::cerr << "ParseRouteAttrs: memcpy routePriority failed" << std::endl;
        return false;
    }

    return true;
}

/**
 * @brief 处理 RTA_TABLE，提取路由所属表 ID。
 */
bool ParseRouteTableAttr(const rtattr* attr, ParsedRouteAttrs* parsed)
{
    if (RTA_PAYLOAD(attr) != static_cast<int>(sizeof(parsed->tableId))) {
        return true;
    }

    if (std::memcpy(&parsed->tableId, RTA_DATA(attr), sizeof(parsed->tableId)) !=
        &parsed->tableId) {
        std::cerr << "ParseRouteAttrs: memcpy tableId failed" << std::endl;
        return false;
    }

    return true;
}

/**
 * @brief 解析路由消息中的关键属性字段。
 * @param family 地址族。
 * @param attr 路由属性链表起始位置。
 * @param payloadLen 路由属性总长度。
 * @return 解析成功时返回属性结构，失败返回空 optional。
 */
std::optional<ParsedRouteAttrs> ParseRouteAttrs(const rtmsg* rtm,
                                                int family,
                                                const rtattr* attr,
                                                int payloadLen)
{
    ParsedRouteAttrs parsed;
    parsed.tableId = rtm->rtm_table;
    for (int len = payloadLen; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        switch (attr->rta_type) {
            case RTA_GATEWAY:
                if (!ParseRouteGatewayAttr(family, attr, &parsed)) {
                    return std::nullopt;
                }
                break;

            case RTA_OIF:
                if (!ParseRouteOifAttr(attr, &parsed)) {
                    return std::nullopt;
                }
                break;

            case RTA_PRIORITY:
                if (!ParseRoutePriorityAttr(attr, &parsed)) {
                    return std::nullopt;
                }
                break;

            case RTA_TABLE:
                if (!ParseRouteTableAttr(attr, &parsed)) {
                    return std::nullopt;
                }
                break;

            default:
                break;
        }
    }
    if (parsed.tableId == RT_TABLE_UNSPEC) {
        parsed.tableId = RT_TABLE_MAIN;
    }
    parsed.matchesTarget = true;
    return parsed;
}

bool RouteMatchesTarget(const ParsedRouteAttrs& parsed)
{
    return parsed.hasOif && parsed.matchesTarget;
}

/**
 * @brief 将命中的路由消息组装为 RouteInfo。
 * @param rtm 路由消息头。
 * @param family 地址族。
 * @param parsed 已解析的路由属性。
 * @return 组装成功返回 RouteInfo，失败返回空 optional。
 */
std::optional<RouteInfo> BuildRouteInfo(const rtmsg* rtm,
                                        int family,
                                        const ParsedRouteAttrs& parsed)
{
    const std::string ifName = GetInterfaceName(parsed.oif);
    std::string gatewayIp;
    if (parsed.hasGateway) {
        char gatewayText[INET6_ADDRSTRLEN] = {};
        const void* gatewayPtr = (family == AF_INET)
                                     ? static_cast<const void*>(&parsed.v4)
                                     : static_cast<const void*>(&parsed.v6);
        const socklen_t gatewayLen = family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
        if (::inet_ntop(family, gatewayPtr, gatewayText, gatewayLen) == nullptr) {
            return std::nullopt;
        }
        gatewayIp = gatewayText;
    }

    return RouteInfo{
        parsed.hasGateway,
        gatewayIp,
        ifName,
        parsed.oif,
        parsed.tableId,
        static_cast<int>(rtm->rtm_dst_len),
        parsed.routePriority,
    };
}

/**
 * @brief 初始化一条邻居表查询请求。
 * @param nlh netlink 消息头输出参数。
 * @param ndm 邻居消息体输出参数。
 * @param family 地址族。
 */
void InitNeighborRequest(nlmsghdr* nlh, ndmsg* ndm, int family)
{
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ndmsg));
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    ndm->ndm_family = static_cast<unsigned char>(family);
}

bool SendNetlinkDump(NetlinkSocket& sock, const void* req, std::size_t len)
{
    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    return ::sendto(sock.get(), req, len, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) >= 0;
}

bool BindProbeSocketToSource(int fd, int family, const RouteLookupOptions& options)
{
    if (!options.hasSource) {
        return true;
    }

    if (family == AF_INET) {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0;
        local.sin_addr = options.sourceV4;
        return ::bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0;
    }

    if (family == AF_INET6) {
        sockaddr_in6 local{};
        local.sin6_family = AF_INET6;
        local.sin6_port = 0;
        local.sin6_addr = options.sourceV6;
        return ::bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0;
    }

    return false;
}

bool TriggerNeighborProbe(int family,
                          const RouteLookupOptions& options,
                          const in_addr& v4,
                          const in6_addr& v6)
{
    const int fd = ::socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::cerr << "TriggerNeighborProbe: socket(SOCK_DGRAM) failed" << std::endl;
        return false;
    }

    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 300000;
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    bool success = false;
    if (!BindProbeSocketToSource(fd, family, options)) {
        std::cerr << "TriggerNeighborProbe: bind(source) failed" << std::endl;
        ::close(fd);
        return false;
    }

    unsigned char probeByte = 0;
    if (family == AF_INET) {
        char ipText[INET_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET, &v4, ipText, sizeof(ipText)) != nullptr) {
            std::cerr << "TriggerNeighborProbe: sending UDP probe to " << ipText << std::endl;
        } else {
            std::cerr << "TriggerNeighborProbe: sending UDP probe to IPv4 target" << std::endl;
        }

        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(9);
        remote.sin_addr = v4;
        success = ::sendto(fd,
                           &probeByte,
                           sizeof(probeByte),
                           0,
                           reinterpret_cast<const sockaddr*>(&remote),
                           sizeof(remote)) >= 0;
    } else if (family == AF_INET6) {
        char ipText[INET6_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET6, &v6, ipText, sizeof(ipText)) != nullptr) {
            std::cerr << "TriggerNeighborProbe: sending UDP probe to " << ipText << std::endl;
        } else {
            std::cerr << "TriggerNeighborProbe: sending UDP probe to IPv6 target" << std::endl;
        }

        sockaddr_in6 remote{};
        remote.sin6_family = AF_INET6;
        remote.sin6_port = htons(9);
        remote.sin6_addr = v6;
        success = ::sendto(fd,
                           &probeByte,
                           sizeof(probeByte),
                           0,
                           reinterpret_cast<const sockaddr*>(&remote),
                           sizeof(remote)) >= 0;
    }

    ::close(fd);
    if (!success) {
        std::cerr << "TriggerNeighborProbe: sendto(probe) failed" << std::endl;
    } else {
        std::cerr << "TriggerNeighborProbe: probe sent successfully" << std::endl;
    }
    return success;
}

std::optional<MacLookupResult> RetryNeighborLookupAfterProbe(int family,
                                                             int expectedIfindex,
                                                             const RouteLookupOptions& options,
                                                             const in_addr& v4,
                                                             const in6_addr& v6)
{
    if (!TriggerNeighborProbe(family, options, v4, v6)) {
        return std::nullopt;
    }

    for (int attempt = 0; attempt < kNeighborProbeRetries; ++attempt) {
        std::cerr << "RetryNeighborLookupAfterProbe: retry " << (attempt + 1) << "/"
                  << kNeighborProbeRetries << std::endl;
        ::usleep(kNeighborProbeRetryDelayUs);
        auto result = FindNeighborMac(family, expectedIfindex, v4, v6);
        if (result.has_value()) {
            return result;
        }
    }

    return std::nullopt;
}

/**
 * @brief 从邻居消息中解析目标 IP 对应的 MAC 与接口名。
 * @param nlh netlink 邻居消息头。
 * @param family 地址族。
 * @param v4 目标 IPv4 地址。
 * @param v6 目标 IPv6 地址。
 * @return 命中时返回 MAC 查询结果，否则返回空 optional。
 */
std::optional<MacLookupResult> ParseNeighborResult(const nlmsghdr* nlh,
                                                   int family,
                                                   int expectedIfindex,
                                                   const in_addr& v4,
                                                   const in6_addr& v6)
{
    if (nlh->nlmsg_type != RTM_NEWNEIGH) {
        return std::nullopt;
    }

    const auto* ndm = reinterpret_cast<const ndmsg*>(NLMSG_DATA(nlh));
    if (ndm->ndm_family != family) {
        return std::nullopt;
    }
    if (expectedIfindex > 0 && ndm->ndm_ifindex != expectedIfindex) {
        return std::nullopt;
    }

    const int payloadLen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ndm));
    if (payloadLen < 0) {
        return std::nullopt;
    }

    const rtattr* attr = reinterpret_cast<const rtattr*>(
        reinterpret_cast<const char*>(ndm) + NLMSG_ALIGN(sizeof(*ndm)));
    bool ipMatch = false;
    std::optional<std::string> macAddress;

    for (int len = payloadLen; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == NDA_DST && family == AF_INET &&
            RTA_PAYLOAD(attr) == static_cast<int>(sizeof(in_addr)) &&
            std::memcmp(RTA_DATA(attr), &v4, sizeof(v4)) == 0) {
            ipMatch = true;
        } else if (attr->rta_type == NDA_DST && family == AF_INET6 &&
                   RTA_PAYLOAD(attr) == static_cast<int>(sizeof(in6_addr)) &&
                   std::memcmp(RTA_DATA(attr), &v6, sizeof(v6)) == 0) {
            ipMatch = true;
        } else if (attr->rta_type == NDA_LLADDR && RTA_PAYLOAD(attr) == 6) {
            macAddress = FormatMac(reinterpret_cast<const unsigned char*>(RTA_DATA(attr)), 6);
        }
    }

    if (!ipMatch || !macAddress.has_value()) {
        return std::nullopt;
    }

    return MacLookupResult{*macAddress, GetInterfaceName(ndm->ndm_ifindex), Source::Neighbor};
}

bool SendRouteLookupRequest(NetlinkSocket& sock,
                            const RouteLookupOptions& options,
                            int family,
                            const in_addr& v4,
                            const in6_addr& v6)
{
    struct {
        nlmsghdr nlh;
        rtmsg rtm;
        char attrbuf[RTA_SPACE(sizeof(in6_addr)) + RTA_SPACE(sizeof(in6_addr)) +
                     RTA_SPACE(sizeof(int)) +
                     RTA_SPACE(sizeof(std::uint32_t))];
    } req{};
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 2;
    req.rtm.rtm_family = static_cast<unsigned char>(family);
    req.rtm.rtm_dst_len = family == AF_INET ? 32 : 128;
    if (options.hasSource) {
        req.rtm.rtm_src_len = family == AF_INET ? 32 : 128;
    }
    if (options.tableId <= 0xFFU) {
        req.rtm.rtm_table = static_cast<unsigned char>(options.tableId);
    } else {
        req.rtm.rtm_table = RT_TABLE_UNSPEC;
    }
    const void* rawIp = family == AF_INET ? static_cast<const void*>(&v4)
                                          : static_cast<const void*>(&v6);
    auto* attr = reinterpret_cast<rtattr*>(
        reinterpret_cast<char*>(&req.nlh) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    const auto dataLen = FamilyAddressSize(family);
    attr->rta_type = RTA_DST;
    attr->rta_len = RTA_LENGTH(dataLen);
    if (std::memcpy(RTA_DATA(attr), rawIp, dataLen) != RTA_DATA(attr)) {
        std::cerr << "SendRouteLookupRequest: memcpy RTA_DST failed" << std::endl;
        return false;
    }
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(dataLen);
    if (options.hasSource) {
        attr = reinterpret_cast<rtattr*>(
            reinterpret_cast<char*>(&req.nlh) + NLMSG_ALIGN(req.nlh.nlmsg_len));
        attr->rta_type = RTA_SRC;
        attr->rta_len = RTA_LENGTH(dataLen);
        const void* rawSource = family == AF_INET ? static_cast<const void*>(&options.sourceV4)
                                                  : static_cast<const void*>(&options.sourceV6);
        if (std::memcpy(RTA_DATA(attr), rawSource, dataLen) != RTA_DATA(attr)) {
            std::cerr << "SendRouteLookupRequest: memcpy RTA_SRC failed" << std::endl;
            return false;
        }
        req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(dataLen);
    }
    if (options.outputInterfaceIndex > 0) {
        attr = reinterpret_cast<rtattr*>(
            reinterpret_cast<char*>(&req.nlh) + NLMSG_ALIGN(req.nlh.nlmsg_len));
        attr->rta_type = RTA_OIF;
        attr->rta_len = RTA_LENGTH(sizeof(options.outputInterfaceIndex));
        if (std::memcpy(RTA_DATA(attr),
                        &options.outputInterfaceIndex,
                        sizeof(options.outputInterfaceIndex)) != RTA_DATA(attr)) {
            std::cerr << "SendRouteLookupRequest: memcpy RTA_OIF failed" << std::endl;
            return false;
        }
        req.nlh.nlmsg_len =
            NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(sizeof(options.outputInterfaceIndex));
    }
    if (options.tableId != RT_TABLE_UNSPEC && options.tableId > 0xFFU) {
        attr = reinterpret_cast<rtattr*>(
            reinterpret_cast<char*>(&req.nlh) + NLMSG_ALIGN(req.nlh.nlmsg_len));
        attr->rta_type = RTA_TABLE;
        attr->rta_len = RTA_LENGTH(sizeof(options.tableId));
        if (std::memcpy(RTA_DATA(attr), &options.tableId, sizeof(options.tableId)) !=
            RTA_DATA(attr)) {
            std::cerr << "SendRouteLookupRequest: memcpy RTA_TABLE failed" << std::endl;
            return false;
        }
        req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(sizeof(options.tableId));
    }
    return SendNetlinkDump(sock, &req, req.nlh.nlmsg_len);
}

/**
 * @brief 通过 UDP connect 让内核完成一次真实路由选择，并提取本地源地址。
 * @param family 地址族。
 * @param v4 目标 IPv4 地址。
 * @param v6 目标 IPv6 地址。
 * @param options 路由查询选项，成功时写入 source 地址。
 * @return 成功返回 true，否则返回 false。
 */
bool DetectPreferredSource(int family,
                           const in_addr& v4,
                           const in6_addr& v6,
                           RouteLookupOptions* options)
{
    const int fd = ::socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::cerr << "DetectPreferredSource: socket(SOCK_DGRAM) failed" << std::endl;
        return false;
    }

    bool success = false;
    if (family == AF_INET) {
        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(9);
        remote.sin_addr = v4;
        if (::connect(fd, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) == 0) {
            sockaddr_in local{};
            socklen_t localLen = sizeof(local);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &localLen) == 0) {
                options->sourceV4 = local.sin_addr;
                options->hasSource = true;
                success = true;
            }
        }
    } else if (family == AF_INET6) {
        sockaddr_in6 remote{};
        remote.sin6_family = AF_INET6;
        remote.sin6_port = htons(9);
        remote.sin6_addr = v6;
        if (::connect(fd, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) == 0) {
            sockaddr_in6 local{};
            socklen_t localLen = sizeof(local);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &localLen) == 0) {
                options->sourceV6 = local.sin6_addr;
                options->hasSource = true;
                success = true;
            }
        }
    }

    ::close(fd);
    if (!success) {
        std::cerr << "DetectPreferredSource: failed to derive preferred source address" << std::endl;
    }
    return success;
}

/**
 * @brief 枚举本机指定地址族的所有单播地址候选，用于多源地址/多 VLAN 场景下逐个尝试路由查找。
 * @param family 地址族。
 * @return 本机地址候选列表。
 */
std::vector<LocalAddressCandidate> ListLocalAddressCandidates(int family)
{
    std::vector<LocalAddressCandidate> candidates;
    IfaddrsGuard ifaddrsGuard;
    if (::getifaddrs(ifaddrsGuard.out()) != 0) {
        std::cerr << "ListLocalAddressCandidates: getifaddrs failed" << std::endl;
        return candidates;
    }

    std::unordered_set<std::string> seen;
    for (ifaddrs* it = ifaddrsGuard.get(); it != nullptr; it = it->ifa_next) {
        if (it->ifa_name == nullptr || it->ifa_addr == nullptr || it->ifa_addr->sa_family != family) {
            continue;
        }
        if ((it->ifa_flags & IFF_UP) == 0) {
            continue;
        }

        char addressText[INET6_ADDRSTRLEN] = {};
        LocalAddressCandidate candidate;
        candidate.interfaceName = it->ifa_name;
        candidate.interfaceIndex = ::if_nametoindex(it->ifa_name);
        if (candidate.interfaceIndex <= 0 || (it->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }
        if (family == AF_INET) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
            candidate.v4 = in->sin_addr;
            if (::inet_ntop(AF_INET, &candidate.v4, addressText, sizeof(addressText)) == nullptr) {
                continue;
            }
        } else if (family == AF_INET6) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(it->ifa_addr);
            candidate.v6 = in6->sin6_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&candidate.v6) || IN6_IS_ADDR_MULTICAST(&candidate.v6)) {
                continue;
            }
            if (::inet_ntop(AF_INET6, &candidate.v6, addressText, sizeof(addressText)) == nullptr) {
                continue;
            }
        } else {
            continue;
        }

        const std::string key = candidate.interfaceName + "|" + addressText;
        if (!seen.insert(key).second) {
            continue;
        }
        candidates.push_back(candidate);
    }
    return candidates;
}

/**
 * @brief 在路由表中查找目标地址对应的最佳网关信息。
 * @param family 地址族。
 * @param v4 目标 IPv4 地址。
 * @param v6 目标 IPv6 地址。
 * @return 查找成功返回最佳网关路由，否则返回空 optional。
 */
std::optional<RouteInfo> FindGatewayRoute(int family,
                                          const RouteLookupOptions& options,
                                          const in_addr& v4,
                                          const in6_addr& v6)
{
    NetlinkSocket sock;
    if (sock.get() < 0) {
        std::cerr << "FindGatewayRoute: socket(AF_NETLINK) failed" << std::endl;
        return std::nullopt;
    }

    if (!SendRouteLookupRequest(sock, options, family, v4, v6)) {
        std::cerr << "FindGatewayRoute: sendto(RTM_GETROUTE) failed" << std::endl;
        return std::nullopt;
    }

    std::vector<char> buffer(kNetlinkBufferSize);
    if (!ReceiveNetlinkBuffer(sock, &buffer)) {
        std::cerr << "FindGatewayRoute: recv(netlink) failed" << std::endl;
        return std::nullopt;
    }

    int remaining = static_cast<int>(buffer.size());
    for (nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buffer.data());
         NLMSG_OK(nlh, remaining);
         nlh = NLMSG_NEXT(nlh, remaining)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            std::cerr << "FindGatewayRoute: NLMSG_ERROR" << std::endl;
            return std::nullopt;
        }

        if (nlh->nlmsg_type != RTM_NEWROUTE) {
            continue;
        }

        const auto* rtm = reinterpret_cast<const rtmsg*>(NLMSG_DATA(nlh));
        if (rtm->rtm_family != family) {
            continue;
        }

        const int payloadLen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
        if (payloadLen < 0) {
            continue;
        }

        const rtattr* attr = reinterpret_cast<const rtattr*>(
            reinterpret_cast<const char*>(rtm) + NLMSG_ALIGN(sizeof(*rtm)));
        auto parsed = ParseRouteAttrs(rtm, family, attr, payloadLen);
        if (!parsed.has_value() || !RouteMatchesTarget(*parsed)) {
            continue;
        }
        if (options.tableId != RT_TABLE_UNSPEC && parsed->tableId != options.tableId) {
            continue;
        }
        return BuildRouteInfo(rtm, family, *parsed);
    }

    std::cerr << "FindGatewayRoute: no matching gateway route found" << std::endl;
    return std::nullopt;
}

/**
 * @brief 判断目标地址是否为本机接口地址，并返回该接口自身的 MAC。
 * @param family 地址族。
 * @param v4 目标 IPv4 地址。
 * @param v6 目标 IPv6 地址。
 * @return 命中本机接口时返回 MAC 查询结果，否则返回空 optional。
 */
std::optional<MacLookupResult> FindLocalInterfaceMac(int family,
                                                     const in_addr& v4,
                                                     const in6_addr& v6)
{
    IfaddrsGuard ifaddrsGuard;
    if (::getifaddrs(ifaddrsGuard.out()) != 0) {
        std::cerr << "FindLocalInterfaceMac: getifaddrs failed" << std::endl;
        return std::nullopt;
    }

    std::unordered_map<std::string, std::string> macByName;
    std::optional<std::string> matchedName;
    const void* rawIp = family == AF_INET ? static_cast<const void*>(&v4) : static_cast<const void*>(&v6);
    for (ifaddrs* it = ifaddrsGuard.get(); it != nullptr; it = it->ifa_next) {
        if (it->ifa_name == nullptr || it->ifa_addr == nullptr) {
            continue;
        }

        if (it->ifa_addr->sa_family == AF_PACKET) {
            const auto* sll = reinterpret_cast<const sockaddr_ll*>(it->ifa_addr);
            if (sll->sll_halen == 6) {
                macByName[it->ifa_name] = FormatMac(sll->sll_addr, sll->sll_halen);
            }
            continue;
        }

        if (it->ifa_addr->sa_family == family && SockaddrEqualsIp(it->ifa_addr, family, rawIp)) {
            matchedName = it->ifa_name;
        }
    }

    if (!matchedName.has_value() || !macByName.count(*matchedName)) {
        std::cerr << "FindLocalInterfaceMac: no local interface MAC matched the target IP" << std::endl;
        return std::nullopt;
    }
    return MacLookupResult{macByName[*matchedName], *matchedName, Source::Local};
}

/**
 * @brief 在邻居缓存中查找目标地址的 MAC。
 * @param family 地址族。
 * @param v4 目标 IPv4 地址。
 * @param v6 目标 IPv6 地址。
 * @return 命中邻居缓存时返回 MAC 查询结果，否则返回空 optional。
 */
std::optional<MacLookupResult> FindNeighborMac(int family,
                                               int expectedIfindex,
                                               const in_addr& v4,
                                               const in6_addr& v6)
{
    NetlinkSocket sock;
    if (sock.get() < 0) {
        std::cerr << "FindNeighborMac: socket(AF_NETLINK) failed" << std::endl;
        return std::nullopt;
    }

    struct {
        nlmsghdr nlh;
        ndmsg ndm;
    } req{};
    InitNeighborRequest(&req.nlh, &req.ndm, family);
    if (!SendNetlinkDump(sock, &req, req.nlh.nlmsg_len)) {
        std::cerr << "FindNeighborMac: sendto(RTM_GETNEIGH) failed" << std::endl;
        return std::nullopt;
    }

    std::vector<char> buffer(kNetlinkBufferSize);
    // netlink dump 结果可能分多批返回，因此这里需要持续接收到结束为止。
    bool receiving = true;
    while (receiving) {
        if (!ReceiveNetlinkBuffer(sock, &buffer)) {
            std::cerr << "FindNeighborMac: recv(netlink) failed" << std::endl;
            return std::nullopt;
        }

        int remaining = static_cast<int>(buffer.size());
        for (nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buffer.data());
             NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                receiving = false;
                std::cerr << "FindNeighborMac: neighbor cache lookup completed without a match"
                          << std::endl;
                return std::nullopt;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                std::cerr << "FindNeighborMac: NLMSG_ERROR" << std::endl;
                return std::nullopt;
            }

            auto result = ParseNeighborResult(nlh, family, expectedIfindex, v4, v6);
            if (result.has_value()) {
                return result;
            }
        }
    }
    return std::nullopt;
}

/**
 * @brief 当目标地址未命中邻居缓存时，回退到目标路由上下文查 MAC。
 * @param family 地址族。
 * @param v4 目标 IPv4 地址。
 * @param v6 目标 IPv6 地址。
 * @return 查找成功返回路由相关的 MAC 查询结果，否则返回空 optional。
 */
std::optional<MacLookupResult> FindRoutedMac(int family,
                                             const RouteLookupOptions& options,
                                             const in_addr& v4,
                                             const in6_addr& v6)
{
    const auto route = FindGatewayRoute(family, options, v4, v6);
    if (!route.has_value()) {
        std::cerr << "FindRoutedMac: route lookup failed" << std::endl;
        return std::nullopt;
    }

    if (!route->hasGateway) {
        auto directMac = FindNeighborMac(family, route->interfaceIndex, v4, v6);
        if (!directMac.has_value()) {
            directMac =
                RetryNeighborLookupAfterProbe(family, route->interfaceIndex, options, v4, v6);
        }
        if (!directMac.has_value()) {
            std::cerr << "FindRoutedMac: direct-route neighbor MAC lookup failed on "
                      << route->interfaceName << std::endl;
            return std::nullopt;
        }

        directMac->source = Source::DirectRoute;
        directMac->interfaceName = route->interfaceName;
        return directMac;
    }

    in_addr gatewayV4{};
    in6_addr gatewayV6{};
    const int gatewayFamily = DetectFamily(route->gatewayIp, &gatewayV4, &gatewayV6);
    if (gatewayFamily == AF_UNSPEC) {
        std::cerr << "FindRoutedMac: gateway IP is invalid: " << route->gatewayIp << std::endl;
        return std::nullopt;
    }

    auto gatewayMac = FindNeighborMac(gatewayFamily, route->interfaceIndex, gatewayV4, gatewayV6);
    if (!gatewayMac.has_value()) {
        gatewayMac =
            RetryNeighborLookupAfterProbe(family, route->interfaceIndex, options, v4, v6);
    }
    if (!gatewayMac.has_value()) {
        std::cerr << "FindRoutedMac: gateway neighbor MAC lookup failed for " << route->gatewayIp
                  << " on " << route->interfaceName << std::endl;
        return std::nullopt;
    }

    gatewayMac->source = Source::Gateway;
    gatewayMac->interfaceName = route->interfaceName;
    return gatewayMac;
}

/**
 * @brief 对外提供统一的 MAC 解析入口。
 * @param ip 目标 IP 字符串。
 * @return 解析成功返回 MAC 查询结果，否则返回空 optional。
 */
std::optional<MacLookupResult> ResolveMacAddress(const std::string& ip,
                                                 const RouteLookupOptions& initialOptions)
{
    in_addr v4{};
    in6_addr v6{};
    const int family = DetectFamily(ip, &v4, &v6);
    if (family == AF_UNSPEC) {
        std::cerr << "ResolveMacAddress: invalid IPv4/IPv6 address" << std::endl;
        return std::nullopt;
    }

    RouteLookupOptions options = initialOptions;

    if (auto local = FindLocalInterfaceMac(family, v4, v6)) {
        return local;
    }

    if (auto neighbor = FindNeighborMac(family, 0, v4, v6)) {
        return neighbor;
    }

    if (!options.hasSource && DetectPreferredSource(family, v4, v6, &options)) {
        auto routed = FindRoutedMac(family, options, v4, v6);
        if (routed.has_value()) {
            return routed;
        }
    }

    for (const auto& candidate : ListLocalAddressCandidates(family)) {
        RouteLookupOptions candidateOptions = initialOptions;
        candidateOptions.hasSource = true;
        candidateOptions.outputInterfaceIndex = candidate.interfaceIndex;
        if (family == AF_INET) {
            candidateOptions.sourceV4 = candidate.v4;
        } else {
            candidateOptions.sourceV6 = candidate.v6;
        }
        auto routed = FindRoutedMac(family, candidateOptions, v4, v6);
        if (routed.has_value()) {
            return routed;
        }
    }

    std::cerr << "ResolveMacAddress: unable to resolve MAC address for target: " << ip
              << std::endl;
    return std::nullopt;
}

/**
 * @brief 程序入口函数。
 * @param argc 命令行参数个数。
 * @param argv 命令行参数数组。
 * @return 成功返回 0，参数错误返回 1，未找到 MAC 返回 2。
 */
int main(int argc, char* argv[])
{
    if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage(argv[0]);
        return 0;
    }

    if (argc != 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    const auto result = ResolveMacAddress(argv[1], RouteLookupOptions{});
    if (!result.has_value()) {
        std::cerr
            << "MAC address not found.\n"
            << "The IP may be invalid, off-link, its ARP/NDP neighbor entry may be absent, "
            << "the policy route may depend on unavailable kernel context, "
            << "or the gateway neighbor entry may not be in the kernel cache.\n";
        return 2;
    }

    std::cout << "IP: " << argv[1] << '\n'
              << "MAC: " << result->macAddress << '\n'
              << "Interface: " << result->interfaceName << '\n'
              << "Source: " << SourceToString(result->source) << '\n';
    return 0;
}
