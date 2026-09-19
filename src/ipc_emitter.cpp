#include "ipc_emitter.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cstdio>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace DPI {

#ifdef _WIN32
std::atomic<int> IPCEmitter::wsa_init_count_{0};

void IPCEmitter::initWSA() {
    if (wsa_init_count_++ == 0) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
}

void IPCEmitter::cleanupWSA() {
    if (--wsa_init_count_ == 0) {
        WSACleanup();
    }
}
#endif

IPCEmitter::IPCEmitter() {
#ifdef _WIN32
    initWSA();
#endif
}

IPCEmitter::~IPCEmitter() {
    disconnect();
#ifdef _WIN32
    cleanupWSA();
#endif
}

std::string IPCEmitter::escapeJSONString(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 8);
    for (char c : input) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

bool IPCEmitter::connect(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(socket_mutex_);

    if (connected_) {
        if (host_ == host && port_ == port) {
            return true;
        }
        // Endpoint changed - disconnect existing socket first
#ifdef _WIN32
        if (sock_ != ~0ULL) {
            ::closesocket(static_cast<SOCKET>(sock_));
            sock_ = ~0ULL;
        }
#else
        if (sock_ >= 0) {
            ::close(sock_);
            sock_ = -1;
        }
#endif
        connected_ = false;
    }

    host_ = host;
    port_ = port;

    struct addrinfo hints{}, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        return false;
    }

#ifdef _WIN32
    SOCKET s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return false;
    }
    sock_ = static_cast<uintptr_t>(s);
#else
    int s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) {
        freeaddrinfo(res);
        return false;
    }
    sock_ = s;
#endif

    if (::connect(static_cast<
#ifdef _WIN32
        SOCKET
#else
        int
#endif
    >(sock_), res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) < 0) {
        freeaddrinfo(res);
#ifdef _WIN32
        ::closesocket(static_cast<SOCKET>(sock_));
        sock_ = ~0ULL;
#else
        ::close(sock_);
        sock_ = -1;
#endif
        connected_ = false;
        return false;
    }

    freeaddrinfo(res);
    connected_ = true;
    return true;
}

void IPCEmitter::disconnect() {
    std::lock_guard<std::mutex> lock(socket_mutex_);
#ifdef _WIN32
    if (sock_ != ~0ULL) {
        ::closesocket(static_cast<SOCKET>(sock_));
        sock_ = ~0ULL;
    }
#else
    if (sock_ >= 0) {
        ::close(sock_);
        sock_ = -1;
    }
#endif
    connected_ = false;
}

bool IPCEmitter::sendRawJson(const std::string& json_str) {
    if (!connected_) {
        return false;
    }

    std::string line = json_str + "\n";
    std::lock_guard<std::mutex> lock(socket_mutex_);

    if (!connected_) {
        return false;
    }

    size_t total_sent = 0;
    while (total_sent < line.size()) {
        int bytes_sent = ::send(
            static_cast<
#ifdef _WIN32
                SOCKET
#else
                int
#endif
            >(sock_),
            line.c_str() + total_sent,
            static_cast<int>(line.size() - total_sent),
            MSG_NOSIGNAL
        );

        if (bytes_sent <= 0) {
#ifdef _WIN32
            if (sock_ != ~0ULL) {
                ::closesocket(static_cast<SOCKET>(sock_));
                sock_ = ~0ULL;
            }
#else
            if (sock_ >= 0) {
                ::close(sock_);
                sock_ = -1;
            }
#endif
            connected_ = false;
            return false;
        }
        total_sent += static_cast<size_t>(bytes_sent);
    }

    return true;
}

void IPCEmitter::emitAppClassified(const FiveTuple& tuple,
                                   const std::string& app,
                                   bool blocked,
                                   const std::string& reason,
                                   size_t packet_bytes) {
    double ts = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string safe_app = escapeJSONString(app.empty() ? "Unknown" : app);
    std::string safe_reason = reason.empty() ? "" : escapeJSONString(reason);

    std::ostringstream ss;
    ss << "{\"event\":\"app_classified\","
       << "\"ts\":" << std::fixed << std::setprecision(3) << ts << ","
       << "\"five_tuple\":{"
       << "\"src_ip\":\"" << escapeJSONString(formatIP(tuple.src_ip)) << "\","
       << "\"src_port\":" << tuple.src_port << ","
       << "\"dst_ip\":\"" << escapeJSONString(formatIP(tuple.dst_ip)) << "\","
       << "\"dst_port\":" << tuple.dst_port << ","
       << "\"proto\":\"" << (tuple.protocol == 6 ? "TCP" : (tuple.protocol == 17 ? "UDP" : "OTHER")) << "\""
       << "},"
       << "\"app\":\"" << safe_app << "\","
       << "\"bytes\":" << packet_bytes << ","
       << "\"blocked\":" << (blocked ? "true" : "false") << ","
       << "\"reason\":" << (safe_reason.empty() ? "null" : ("\"" + safe_reason + "\""))
       << "}";

    sendRawJson(ss.str());
}

void IPCEmitter::emitAnomaly(const std::string& type,
                             const std::string& src_ip,
                             const std::string& target_ip,
                             int ports_seen) {
    double ts = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::ostringstream ss;
    ss << "{\"event\":\"anomaly\","
       << "\"ts\":" << std::fixed << std::setprecision(3) << ts << ","
       << "\"type\":\"" << escapeJSONString(type) << "\","
       << "\"detail\":{"
       << "\"src_ip\":\"" << escapeJSONString(src_ip) << "\","
       << "\"target\":\"" << escapeJSONString(target_ip) << "\","
       << "\"ports_seen\":" << ports_seen
       << "}}";

    sendRawJson(ss.str());
}

void IPCEmitter::emitStats(const DPIStats& stats, double throughput_bps) {
    double ts = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::ostringstream ss;
    ss << "{\"event\":\"stats\","
       << "\"ts\":" << std::fixed << std::setprecision(1) << ts << ","
       << "\"total_packets\":" << stats.total_packets.load() << ","
       << "\"total_bytes\":" << stats.total_bytes.load() << ","
       << "\"throughput_bps\":" << std::fixed << std::setprecision(2) << throughput_bps << ","
       << "\"app_breakdown\":{";

    bool first = true;
    for (size_t i = 0; i < static_cast<size_t>(AppType::APP_COUNT); ++i) {
        uint64_t count = stats.app_counts[i].load();
        if (count > 0) {
            if (!first) ss << ",";
            ss << "\"" << escapeJSONString(appTypeToString(static_cast<AppType>(i))) << "\":" << count;
            first = false;
        }
    }
    if (first) {
        ss << "\"Unknown\":0";
    }
    ss << "},"
       << "\"blocked_total\":" << stats.blocked_total.load() << ","
       << "\"blocked_reasons\":{"
       << "\"IP\":" << stats.blocked_by_ip.load() << ","
       << "\"PORT\":" << stats.blocked_by_port.load() << ","
       << "\"APP\":" << stats.blocked_by_app.load() << ","
       << "\"DOMAIN\":" << stats.blocked_by_domain.load() << ","
       << "\"MALICIOUS\":" << stats.blocked_by_malicious.load() << ","
       << "\"VPN_DETECTED\":" << stats.blocked_by_vpn.load()
       << "},"
       << "\"scan_alerts\":" << stats.scan_alerts.load() << ","
       << "\"syn_flood_alerts\":" << stats.syn_flood_alerts.load() << ","
       << "\"dns_tunnel_alerts\":" << stats.dns_tunnel_alerts.load()
       << "}";

    sendRawJson(ss.str());
}

} // namespace DPI
