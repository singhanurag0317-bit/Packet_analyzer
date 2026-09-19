#ifndef DPI_IPC_EMITTER_H
#define DPI_IPC_EMITTER_H

#include "types.h"
#include <string>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace DPI {

class IPCEmitter {
public:
    IPCEmitter();
    ~IPCEmitter();

    // Connect to dashboard IPC server on host:port (default 127.0.0.1:9000)
    bool connect(const std::string& host = "127.0.0.1", uint16_t port = 9000);
    void disconnect();
    bool isConnected() const { return connected_.load(); }

    // Send a pre-formatted JSON string (automatically appends '\n')
    bool sendRawJson(const std::string& json_str);

    // JSON string escaping helper
    static std::string escapeJSONString(const std::string& input);

    // Emit per-connection classification event (§4.2 schema)
    void emitAppClassified(const FiveTuple& tuple,
                           const std::string& app,
                           bool blocked,
                           const std::string& reason = "",
                           size_t packet_bytes = 0);

    // Emit security anomaly alert (§4.2 schema)
    void emitAnomaly(const std::string& type,
                     const std::string& src_ip,
                     const std::string& target_ip,
                     int ports_seen);

    // Emit aggregate statistics update (§4.3 schema)
    void emitStats(const DPIStats& stats, double throughput_bps);

private:
    std::string host_{"127.0.0.1"};
    uint16_t port_{9000};
    std::atomic<bool> connected_{false};
    mutable std::mutex socket_mutex_;

#ifdef _WIN32
    uintptr_t sock_{~0ULL}; // INVALID_SOCKET
    static std::atomic<int> wsa_init_count_;
    static void initWSA();
    static void cleanupWSA();
#else
    int sock_{-1};
#endif
};

} // namespace DPI

#endif // DPI_IPC_EMITTER_H
