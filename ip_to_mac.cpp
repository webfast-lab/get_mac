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
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

constexpr int NO_NEGATIVE_1 = -1;
constexpr int NO_0 = 0;
constexpr int NO_1 = 1;
constexpr int NO_2 = 2;
constexpr int NO_3 = 3;
constexpr int NO_6 = 6;
constexpr int NO_9 = 9;
constexpr int NO_32 = 32;
constexpr int NO_128 = 128;
constexpr std::size_t NO_1024 = 1024;
constexpr useconds_t NO_100000 = 100000;
constexpr suseconds_t NO_300000 = 300000;
constexpr char NO_ZERO_CHAR = '0';

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
    int interfaceIndex = NO_0;
    std::uint32_t tableId = RT_TABLE_UNSPEC;
};

struct ParsedRouteAttrs {
    bool hasGateway = false;
    bool hasOif = false;
    in_addr v4{};
    in6_addr v6{};
    int oif = NO_0;
    std::uint32_t tableId = RT_TABLE_UNSPEC;
};

struct RouteLookupOptions {
    in_addr sourceV4{};
    in6_addr sourceV6{};
    int outputInterfaceIndex = NO_0;
};

struct LocalAddressCandidate {
    std::string interfaceName;
    int interfaceIndex = NO_0;
    in_addr v4{};
    in6_addr v6{};
};

struct ParsedIpLiteral {
    std::string original;
    std::string normalized;
    int family = AF_UNSPEC;
    in_addr v4{};
    in6_addr v6{};
};

struct MacResolveRequest {
    ParsedIpLiteral localServiceIp;
    ParsedIpLiteral tcpSourceIp;
};

constexpr std::size_t kNetlinkBufferSize = NO_32 * NO_1024;
constexpr int kNeighborProbeRetries = NO_1;
constexpr useconds_t kNeighborProbeRetryDelayUs = NO_100000;

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
    return NO_0;
}

std::optional<int> NetlinkPayloadLength(const nlmsghdr* nlh, std::size_t headerSize)
{
    const std::size_t alignedHeaderSize = NLMSG_LENGTH(headerSize);
    if (nlh->nlmsg_len < alignedHeaderSize) {
        return std::nullopt;
    }
    const std::size_t payloadLength = nlh->nlmsg_len - alignedHeaderSize;
    if (payloadLength > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return std::nullopt;
    }
    return static_cast<int>(payloadLength);
}

std::uint16_t RtAttrLength(std::size_t payloadLength)
{
    return static_cast<std::uint16_t>(RTA_LENGTH(payloadLength));
}

std::uint32_t AlignedNetlinkLength(std::uint32_t currentLength, std::size_t payloadLength)
{
    return static_cast<std::uint32_t>(NLMSG_ALIGN(currentLength) + RTA_LENGTH(payloadLength));
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
    oss << std::hex << std::setfill(NO_ZERO_CHAR);
    for (std::size_t i = NO_0; i < len; ++i) {
        if (i != NO_0) {
            oss << ':';
        }
        oss << std::setw(NO_2) << static_cast<unsigned int>(bytes[i]);
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
        return std::memcmp(&in->sin_addr, rawIp, sizeof(in_addr)) == NO_0;
    }

    if (family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        return std::memcmp(&in6->sin6_addr, rawIp, sizeof(in6_addr)) == NO_0;
    }

    return false;
}

std::string NormalizeIpLiteral(const std::string& ip)
{
    std::string normalized = ip;
    if (!ip.empty() && ip.front() == '[') {
        const std::size_t closeBracket = ip.find(']');
        if (closeBracket != std::string::npos && closeBracket > NO_1) {
            normalized = ip.substr(NO_1, closeBracket - NO_1);
        } else {
            std::cerr << "NormalizeIpLiteral: invalid bracketed IP literal" << std::endl;
        }
    }
    return normalized;
}

ParsedIpLiteral ParseIpLiteral(const std::string& ip, const char* label)
{
    ParsedIpLiteral parsed;
    parsed.original = ip;
    parsed.normalized = NormalizeIpLiteral(ip);
    if (::inet_pton(AF_INET, parsed.normalized.c_str(), &parsed.v4) == NO_1) {
        parsed.family = AF_INET;
    } else if (::inet_pton(AF_INET6, parsed.normalized.c_str(), &parsed.v6) == NO_1) {
        parsed.family = AF_INET6;
    } else {
        std::cerr << "ParseIpLiteral: invalid " << label << std::endl;
    }
    return parsed;
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
    const ParsedIpLiteral parsed = ParseIpLiteral(ip, "IP address");
    if (parsed.family == AF_INET) {
        *v4 = parsed.v4;
    } else if (parsed.family == AF_INET6) {
        *v6 = parsed.v6;
    }
    return parsed.family;
}

void PrintUsage(const char* argv0)
{
    std::cerr << "Usage: " << argv0 << " <local-service-IP> <tcp-source-IP>\n";
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
        if (fd_ >= NO_0) {
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
    int fd_ = NO_NEGATIVE_1;
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

std::string FormatErrno(int errorNumber)
{
    return std::to_string(errorNumber) + " (" + std::strerror(errorNumber) + ")";
}

std::optional<LocalAddressCandidate> FindLocalAddressCandidateByIp(int family,
                                                                    const in_addr& v4,
                                                                    const in6_addr& v6)
{
    IfaddrsGuard ifaddrsGuard;
    if (::getifaddrs(ifaddrsGuard.out()) != NO_0) {
        std::cerr << "FindLocalAddressCandidateByIp: getifaddrs failed" << std::endl;
        return std::nullopt;
    }

    const void* rawIp = family == AF_INET ? static_cast<const void*>(&v4)
                                          : static_cast<const void*>(&v6);
    for (ifaddrs* it = ifaddrsGuard.get(); it != nullptr; it = it->ifa_next) {
        if (it->ifa_name == nullptr || it->ifa_addr == nullptr ||
            it->ifa_addr->sa_family != family) {
            continue;
        }
        if (!SockaddrEqualsIp(it->ifa_addr, family, rawIp)) {
            continue;
        }

        LocalAddressCandidate candidate;
        candidate.interfaceName = it->ifa_name;
        candidate.interfaceIndex = ::if_nametoindex(it->ifa_name);
        if (candidate.interfaceIndex <= NO_0) {
            std::cerr << "FindLocalAddressCandidateByIp: if_nametoindex failed for "
                      << candidate.interfaceName << std::endl;
            return std::nullopt;
        }
        if (family == AF_INET) {
            candidate.v4 = v4;
        } else {
            candidate.v6 = v6;
        }
        return candidate;
    }
    return std::nullopt;
}

std::optional<RouteLookupOptions> BuildSourceRouteOptions(const ParsedIpLiteral& sourceIp,
                                                          int targetFamily)
{
    if (sourceIp.family == AF_UNSPEC) {
        std::cerr << "BuildSourceRouteOptions: invalid local service IP" << std::endl;
        return std::nullopt;
    }
    if (sourceIp.family != targetFamily) {
        std::cerr << "BuildSourceRouteOptions: local service IP family does not match target IP"
                  << std::endl;
        return std::nullopt;
    }

    RouteLookupOptions options;
    if (targetFamily == AF_INET) {
        options.sourceV4 = sourceIp.v4;
    } else {
        options.sourceV6 = sourceIp.v6;
    }

    const auto sourceCandidate =
        FindLocalAddressCandidateByIp(targetFamily, sourceIp.v4, sourceIp.v6);
    if (sourceCandidate.has_value()) {
        options.outputInterfaceIndex = sourceCandidate->interfaceIndex;
    } else {
        std::cerr << "BuildSourceRouteOptions: local service IP not found on local interfaces"
                  << std::endl;
    }
    return options;
}

MacResolveRequest BuildMacResolveRequest(const std::string& localServiceIp,
                                         const std::string& tcpSourceIp)
{
    return MacResolveRequest{
        ParseIpLiteral(localServiceIp, "local service IP"),
        ParseIpLiteral(tcpSourceIp, "tcp source IP"),
    };
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
        const ssize_t received = ::recv(sock.get(), buffer->data(), buffer->size(), NO_0);
        if (received >= NO_0) {
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
    if (addressSize == NO_0 || payloadSize != addressSize) {
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
    return parsed;
}

/**
 * @brief 将命中的路由消息组装为 RouteInfo。
 * @param family 地址族。
 * @param parsed 已解析的路由属性。
 * @return 组装成功返回 RouteInfo，失败返回空 optional。
 */
std::optional<RouteInfo> BuildRouteInfo(int family,
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
    nlh->nlmsg_seq = NO_1;
    ndm->ndm_family = static_cast<unsigned char>(family);
}

bool SendNetlinkDump(NetlinkSocket& sock, const void* req, std::size_t len)
{
    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    return ::sendto(sock.get(), req, len, NO_0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) >=
           NO_0;
}

bool BindProbeSocketToSource(int fd, int family, const RouteLookupOptions& options)
{
    if (family == AF_INET) {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = NO_0;
        local.sin_addr = options.sourceV4;
        if (::bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == NO_0) {
            return true;
        }
    const int savedErrno = errno;
        std::cerr << "BindProbeSocketToSource: bind IPv4 source failed, errno="
                  << FormatErrno(savedErrno) << std::endl;
        return false;
    }

    if (family == AF_INET6) {
        sockaddr_in6 local{};
        local.sin6_family = AF_INET6;
        local.sin6_port = NO_0;
        local.sin6_addr = options.sourceV6;
        if (::bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == NO_0) {
            return true;
        }
        const int savedErrno = errno;
        std::cerr << "BindProbeSocketToSource: bind IPv6 source failed, errno="
                  << FormatErrno(savedErrno) << std::endl;
        return false;
    }

    return false;
}

bool TriggerNeighborProbe(int family,
                          const RouteLookupOptions& options,
                          const in_addr& v4,
                          const in6_addr& v6)
{
    const int fd = ::socket(family, SOCK_DGRAM, NO_0);
    if (fd < NO_0) {
        const int savedErrno = errno;
        std::cerr << "TriggerNeighborProbe: socket(SOCK_DGRAM) failed, errno="
                  << FormatErrno(savedErrno) << std::endl;
        return false;
    }

    timeval timeout{};
    timeout.tv_sec = NO_0;
    timeout.tv_usec = NO_300000;
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    bool success = false;
    if (!BindProbeSocketToSource(fd, family, options)) {
        std::cerr << "TriggerNeighborProbe: bind(source) failed" << std::endl;
        ::close(fd);
        return false;
    }

    unsigned char probeByte = NO_0;
    int sendErrno = NO_0;
    if (family == AF_INET) {
        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(NO_9);
        remote.sin_addr = v4;
        const ssize_t sent = ::sendto(fd,
                                      &probeByte,
                                      sizeof(probeByte),
                                      NO_0,
                                      reinterpret_cast<const sockaddr*>(&remote),
                                      sizeof(remote));
        success = sent >= NO_0;
        if (!success) {
            sendErrno = errno;
        }
    } else if (family == AF_INET6) {
        sockaddr_in6 remote{};
        remote.sin6_family = AF_INET6;
        remote.sin6_port = htons(NO_9);
        remote.sin6_addr = v6;
        const ssize_t sent = ::sendto(fd,
                                      &probeByte,
                                      sizeof(probeByte),
                                      NO_0,
                                      reinterpret_cast<const sockaddr*>(&remote),
                                      sizeof(remote));
        success = sent >= NO_0;
        if (!success) {
            sendErrno = errno;
        }
    }

    ::close(fd);
    if (!success) {
        std::cerr << "TriggerNeighborProbe: sendto(probe) failed, errno="
                  << FormatErrno(sendErrno) << std::endl;
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

    for (int attempt = NO_0; attempt < kNeighborProbeRetries; ++attempt) {
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
    if (expectedIfindex > NO_0 && ndm->ndm_ifindex != expectedIfindex) {
        return std::nullopt;
    }

    const auto payloadLen = NetlinkPayloadLength(nlh, sizeof(*ndm));
    if (!payloadLen.has_value()) {
        return std::nullopt;
    }

    const rtattr* attr = reinterpret_cast<const rtattr*>(
        reinterpret_cast<const char*>(ndm) + NLMSG_ALIGN(sizeof(*ndm)));
    bool ipMatch = false;
    std::optional<std::string> macAddress;

    for (int len = *payloadLen; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == NDA_DST && family == AF_INET &&
            RTA_PAYLOAD(attr) == static_cast<int>(sizeof(in_addr)) &&
            std::memcmp(RTA_DATA(attr), &v4, sizeof(v4)) == NO_0) {
            ipMatch = true;
        } else if (attr->rta_type == NDA_DST && family == AF_INET6 &&
                   RTA_PAYLOAD(attr) == static_cast<int>(sizeof(in6_addr)) &&
                   std::memcmp(RTA_DATA(attr), &v6, sizeof(v6)) == NO_0) {
            ipMatch = true;
        } else if (attr->rta_type == NDA_LLADDR && RTA_PAYLOAD(attr) == NO_6) {
            macAddress = FormatMac(reinterpret_cast<const unsigned char*>(RTA_DATA(attr)), NO_6);
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
    req.nlh.nlmsg_seq = NO_2;
    req.rtm.rtm_family = static_cast<unsigned char>(family);
    req.rtm.rtm_dst_len = family == AF_INET ? NO_32 : NO_128;
    req.rtm.rtm_src_len = family == AF_INET ? NO_32 : NO_128;
    req.rtm.rtm_table = RT_TABLE_UNSPEC;
    const void* rawIp = family == AF_INET ? static_cast<const void*>(&v4)
                                          : static_cast<const void*>(&v6);
    auto* attr = reinterpret_cast<rtattr*>(
        reinterpret_cast<char*>(&req.nlh) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    const auto dataLen = FamilyAddressSize(family);
    attr->rta_type = RTA_DST;
    attr->rta_len = RtAttrLength(dataLen);
    if (std::memcpy(RTA_DATA(attr), rawIp, dataLen) != RTA_DATA(attr)) {
        std::cerr << "SendRouteLookupRequest: memcpy RTA_DST failed" << std::endl;
        return false;
    }
    req.nlh.nlmsg_len = AlignedNetlinkLength(req.nlh.nlmsg_len, dataLen);
    attr = reinterpret_cast<rtattr*>(
        reinterpret_cast<char*>(&req.nlh) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    attr->rta_type = RTA_SRC;
    attr->rta_len = RtAttrLength(dataLen);
    const void* rawSource = family == AF_INET ? static_cast<const void*>(&options.sourceV4)
                                              : static_cast<const void*>(&options.sourceV6);
    if (std::memcpy(RTA_DATA(attr), rawSource, dataLen) != RTA_DATA(attr)) {
        std::cerr << "SendRouteLookupRequest: memcpy RTA_SRC failed" << std::endl;
        return false;
    }
    req.nlh.nlmsg_len = AlignedNetlinkLength(req.nlh.nlmsg_len, dataLen);
    if (options.outputInterfaceIndex > NO_0) {
        attr = reinterpret_cast<rtattr*>(
            reinterpret_cast<char*>(&req.nlh) + NLMSG_ALIGN(req.nlh.nlmsg_len));
        attr->rta_type = RTA_OIF;
        attr->rta_len = RtAttrLength(sizeof(options.outputInterfaceIndex));
        if (std::memcpy(RTA_DATA(attr),
                        &options.outputInterfaceIndex,
                        sizeof(options.outputInterfaceIndex)) != RTA_DATA(attr)) {
            std::cerr << "SendRouteLookupRequest: memcpy RTA_OIF failed" << std::endl;
            return false;
        }
        req.nlh.nlmsg_len =
            AlignedNetlinkLength(req.nlh.nlmsg_len, sizeof(options.outputInterfaceIndex));
    }
    return SendNetlinkDump(sock, &req, req.nlh.nlmsg_len);
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
    if (sock.get() < NO_0) {
        const int savedErrno = errno;
        std::cerr << "FindGatewayRoute: socket(AF_NETLINK) failed, errno="
                  << FormatErrno(savedErrno) << std::endl;
        return std::nullopt;
    }

    if (!SendRouteLookupRequest(sock, options, family, v4, v6)) {
        const int savedErrno = errno;
        std::cerr << "FindGatewayRoute: sendto(RTM_GETROUTE) failed, errno="
                  << FormatErrno(savedErrno) << std::endl;
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

        const auto payloadLen = NetlinkPayloadLength(nlh, sizeof(*rtm));
        if (!payloadLen.has_value()) {
            continue;
        }

        const rtattr* attr = reinterpret_cast<const rtattr*>(
            reinterpret_cast<const char*>(rtm) + NLMSG_ALIGN(sizeof(*rtm)));
        auto parsed = ParseRouteAttrs(rtm, family, attr, *payloadLen);
        if (!parsed.has_value() || !parsed->hasOif) {
            continue;
        }
        return BuildRouteInfo(family, *parsed);
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
    if (::getifaddrs(ifaddrsGuard.out()) != NO_0) {
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
            if (sll->sll_halen == NO_6) {
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
    if (sock.get() < NO_0) {
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
        std::cerr << "FindRoutedMac: gateway IP is invalid" << std::endl;
        return std::nullopt;
    }

    auto gatewayMac = FindNeighborMac(gatewayFamily, route->interfaceIndex, gatewayV4, gatewayV6);
    if (!gatewayMac.has_value()) {
        gatewayMac =
            RetryNeighborLookupAfterProbe(gatewayFamily,
                                          route->interfaceIndex,
                                          options,
                                          gatewayV4,
                                          gatewayV6);
    }
    if (!gatewayMac.has_value()) {
        std::cerr << "FindRoutedMac: gateway neighbor MAC lookup failed on "
                  << route->interfaceName << std::endl;
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
std::optional<MacLookupResult> ResolveMacAddressWithRoute(const ParsedIpLiteral& tcpSourceIp,
                                                          const RouteLookupOptions& options)
{
    if (tcpSourceIp.family == AF_UNSPEC) {
        std::cerr << "ResolveMacAddressWithRoute: invalid tcp source IP" << std::endl;
        return std::nullopt;
    }

    if (auto local = FindLocalInterfaceMac(tcpSourceIp.family, tcpSourceIp.v4, tcpSourceIp.v6)) {
        return local;
    }

    if (auto neighbor = FindNeighborMac(tcpSourceIp.family, NO_0, tcpSourceIp.v4, tcpSourceIp.v6)) {
        return neighbor;
    }

    auto routed = FindRoutedMac(tcpSourceIp.family, options, tcpSourceIp.v4, tcpSourceIp.v6);
    if (routed.has_value()) {
        return routed;
    }

    std::cerr << "ResolveMacAddressWithRoute: explicit local service IP route lookup failed"
              << std::endl;
    return std::nullopt;
}

std::optional<MacLookupResult> ResolveMacAddress(const MacResolveRequest& request)
{
    if (request.tcpSourceIp.family == AF_UNSPEC) {
        std::cerr << "ResolveMacAddress: invalid tcp source IP" << std::endl;
        return std::nullopt;
    }

    const auto sourceOptions =
        BuildSourceRouteOptions(request.localServiceIp, request.tcpSourceIp.family);
    if (!sourceOptions.has_value()) {
        return std::nullopt;
    }

    return ResolveMacAddressWithRoute(request.tcpSourceIp, *sourceOptions);
}

/**
 * @brief 程序入口函数。
 * @param argc 命令行参数个数。
 * @param argv 命令行参数数组。
 * @return 成功返回 NO_0，参数错误返回 NO_1，未找到 MAC 返回 NO_2。
 */
int main(int argc, char* argv[])
{
    if (argc == NO_2 && (std::string(argv[NO_1]) == "--help" || std::string(argv[NO_1]) == "-h")) {
        PrintUsage(argv[NO_0]);
        return NO_0;
    }

    if (argc != NO_3) {
        PrintUsage(argv[NO_0]);
        return NO_1;
    }

    const MacResolveRequest request = BuildMacResolveRequest(argv[NO_1], argv[NO_2]);
    const auto result = ResolveMacAddress(request);
    if (!result.has_value()) {
        std::cerr
            << "MAC address not found.\n"
            << "The IP may be invalid, off-link, its ARP/NDP neighbor entry may be absent, "
            << "the policy route may depend on unavailable kernel context, "
            << "or the gateway neighbor entry may not be in the kernel cache.\n";
        return NO_2;
    }

    std::cout << "MAC: " << result->macAddress << '\n'
              << "Interface: " << result->interfaceName << '\n'
              << "Source: " << SourceToString(result->source) << '\n';
    return NO_0;
}
