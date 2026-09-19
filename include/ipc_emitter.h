#ifndef DPI_IPC_EMITTER_H
#define DPI_IPC_EMITTER_H

#include "types.h"
#include "thread_safe_queue.h"
#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include <cstdint>

namespace DPI {

class IPCEmitter {
public:
    IPCEmitter();
    ~IPCEmitter();

    // Configure connection endpoint (default 127.0.0.1:9000)
    bool connect(const std::string& host = "127.0.0.1", uint16_t port = 9000);
    void disconnect();
    bool isConnected() const { return connected_.load(); }

    // Enqueue a pre-formatted JSON string (non-blocking for fast-path, drops if queue full)
    bool sendRawJson(const std::string& json_str);

    // JSON string escaping helper
    static std::string escapeJSONString(const std::string& input);

    // Emit per-connection classification event (§4.2 schema) - non-blocking
    void emitAppClassified(const FiveTuple& tuple,
                           const std::string& app,
                           bool blocked,
                           const std::string& reason = "",
                           size_t packet_bytes = 0);

    // Emit security anomaly alert (§4.2 schema) - non-blocking
    void emitAnomaly(const std::string& type,
                     const std::string& src_ip,
                     const std::string& target_ip,
                     int ports_seen);

    // Emit aggregate statistics update (§4.3 schema) - non-blocking
    void emitStats(const DPIStats& stats, double throughput_bps);

private:
    std::string host_{"127.0.0.1"};
    uint16_t port_{9000};
    std::atomic<bool> connected_{false};
    std::atomic<bool> running_{true};
    mutable std::mutex socket_mutex_;

    ThreadSafeQueue<std::string> queue_{10000};
    std::thread sender_thread_;

    void senderLoop();
    bool internalSend(const std::string& line);
    bool internalConnect();
    void closeSocket();

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
