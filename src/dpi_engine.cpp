#include "dpi_engine.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>

namespace DPI {

// ============================================================================
// DPIEngine Implementation
// ============================================================================

DPIEngine::DPIEngine(const Config& config)
    : config_(config), output_queue_(10000) {
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    DPI ENGINE v1.0                            ║\n";
    std::cout << "║               Deep Packet Inspection System                   ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Configuration:                                                ║\n";
    std::cout << "║   Load Balancers:    " << std::setw(3) << config.num_load_balancers << "                                       ║\n";
    std::cout << "║   FPs per LB:        " << std::setw(3) << config.fps_per_lb << "                                       ║\n";
    std::cout << "║   Total FP threads:  " << std::setw(3) << (config.num_load_balancers * config.fps_per_lb) << "                                       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

DPIEngine::~DPIEngine() {
    stop();
}

bool DPIEngine::initialize() {
    // Create rule manager
    rule_manager_ = std::make_unique<RuleManager>();
    
    // Load rules if specified
    if (!config_.rules_file.empty()) {
        rule_manager_->loadRules(config_.rules_file);
    }

    // Create IPC emitter if enabled
    if (config_.enable_ipc) {
        ipc_emitter_ = std::make_unique<IPCEmitter>();
        if (!ipc_emitter_->connect(config_.ipc_host, config_.ipc_port)) {
            std::cout << "[DPIEngine] IPC emitter enabled (" << config_.ipc_host << ":" << config_.ipc_port 
                      << ") - waiting for server connection\n";
        } else {
            std::cout << "[DPIEngine] Connected IPC emitter to " << config_.ipc_host << ":" << config_.ipc_port << "\n";
        }
    }
    
    // Create output callback
    auto output_cb = [this](const PacketJob& job, PacketAction action) {
        handleOutput(job, action);
    };
    
    // Create FP manager (creates FP threads and their queues)
    int total_fps = config_.num_load_balancers * config_.fps_per_lb;
    fp_manager_ = std::make_unique<FPManager>(total_fps, rule_manager_.get(), output_cb, ipc_emitter_.get(), &stats_);
    
    // Create LB manager (creates LB threads, connects to FP queues)
    lb_manager_ = std::make_unique<LBManager>(
        config_.num_load_balancers,
        config_.fps_per_lb,
        fp_manager_->getQueuePtrs()
    );
    
    // Create global connection table
    global_conn_table_ = std::make_unique<GlobalConnectionTable>(total_fps);
    for (int i = 0; i < total_fps; i++) {
        global_conn_table_->registerTracker(i, &fp_manager_->getFP(i).getConnectionTracker());
    }
    
    std::cout << "[DPIEngine] Initialized successfully\n";
    return true;
}

void DPIEngine::start() {
    if (running_) return;
    
    running_ = true;
    processing_complete_ = false;
    
    // Start output thread
    output_thread_ = std::thread(&DPIEngine::outputThreadFunc, this);

    // Start IPC thread if IPC enabled
    if (config_.enable_ipc) {
        ipc_thread_ = std::thread(&DPIEngine::ipcThreadFunc, this);
    }
    
    // Start FP threads
    fp_manager_->startAll();
    
    // Start LB threads
    lb_manager_->startAll();
    
    std::cout << "[DPIEngine] All threads started\n";
}

void DPIEngine::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Stop LB threads first (they feed FPs)
    if (lb_manager_) {
        lb_manager_->stopAll();
    }
    
    // Stop FP threads
    if (fp_manager_) {
        fp_manager_->stopAll();
    }
    
    // Stop output thread
    output_queue_.shutdown();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }

    // Disconnect IPC emitter so pending sends unblock immediately
    if (ipc_emitter_) {
        ipc_emitter_->disconnect();
    }

    if (ipc_thread_.joinable()) {
        ipc_thread_.join();
    }
    
    std::cout << "[DPIEngine] All threads stopped\n";
}

void DPIEngine::ipcThreadFunc() {
    uint64_t last_bytes = 0;
    auto last_time = std::chrono::steady_clock::now();

    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (!running_) break;

        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - last_time).count();
        uint64_t current_bytes = stats_.total_bytes.load();
        double throughput_bps = 0.0;
        if (dt > 0.0 && current_bytes >= last_bytes) {
            throughput_bps = ((current_bytes - last_bytes) * 8.0) / dt;
        }
        last_bytes = current_bytes;
        last_time = now;

        if (ipc_emitter_) {
            if (!ipc_emitter_->isConnected()) {
                ipc_emitter_->connect(config_.ipc_host, config_.ipc_port);
            }
            if (ipc_emitter_->isConnected()) {
                ipc_emitter_->emitStats(stats_, throughput_bps);
            }
        }
    }
}

void DPIEngine::waitForCompletion() {
    // Wait for reader to finish
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    
    // Wait a bit for queues to drain
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Signal completion
    processing_complete_ = true;
}

bool DPIEngine::processFile(const std::string& input_file,
                            const std::string& output_file) {
    
    std::cout << "\n[DPIEngine] Processing: " << input_file << "\n";
    std::cout << "[DPIEngine] Output to:  " << output_file << "\n\n";
    
    FileCapture source;
    std::string error;
    if (!source.open(input_file, error)) {
        std::cerr << "[DPIEngine] Error: " << error << "\n";
        return false;
    }
    
    return runCapture(source, output_file);
}

bool DPIEngine::processLive(const std::string& interface,
                            const std::string& output_file) {
    
    std::cout << "\n[DPIEngine] Live capture on interface: " << interface << "\n";
    if (!output_file.empty()) {
        std::cout << "[DPIEngine] Output to:  " << output_file << "\n";
    }
    std::cout << "[DPIEngine] Press Ctrl+C to stop.\n\n";
    
    LiveCapture source;
    std::string error;
    if (!source.open(interface, error)) {
        std::cerr << "[DPIEngine] Error: " << error << "\n";
        return false;
    }
    
    return runCapture(source, output_file);
}

bool DPIEngine::runCapture(CaptureSource& source,
                           const std::string& output_file) {
    // Initialize if not already done
    if (!rule_manager_) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Open output file (optional in live mode)
    if (!output_file.empty()) {
        output_file_.open(output_file, std::ios::binary);
        if (!output_file_.is_open()) {
            std::cerr << "[DPIEngine] Error: Cannot open output file\n";
            return false;
        }
        if (source.globalHeader()) {
            writeOutputHeader(*source.globalHeader());
        }
    }
    
    // Start processing threads
    start();
    stop_capture_ = false;
    
    // Start reader thread against the capture source
    reader_finished_ = false;
    reader_thread_ = std::thread(&DPIEngine::readerThreadLoop, this, &source);
    
    if (source.isLive()) {
        // Live mode: run until stopCapture() is requested (Ctrl+C) or the
        // reader ends (fatal capture error).
        while (!stop_capture_.load() && !reader_finished_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        // The reader thread sees the stop flag and finishes; join it.
        if (reader_thread_.joinable()) {
            reader_thread_.join();
        }
        // Give the pipeline a moment to drain the final packets.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        processing_complete_ = true;
    } else {
        // File mode: reader thread finishes on its own.
        if (reader_thread_.joinable()) {
            reader_thread_.join();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        processing_complete_ = true;
    }
    
    // Stop all threads
    stop();
    
    // Close output file
    if (output_file_.is_open()) {
        output_file_.close();
    }
    
    std::cout << "\n";
    if (source.isLive()) {
        std::cout << "[DPIEngine] Live capture stopped.\n";
    } else {
        std::cout << "[DPIEngine] Processing complete!\n";
        std::cout << "[DPIEngine] Output written to: " << output_file << "\n";
    }
    std::cout << generateReport();
    std::cout << fp_manager_->generateClassificationReport();
    
    return true;
}

void DPIEngine::readerThreadLoop(CaptureSource* source) {
    CapturePacket raw;
    PacketAnalyzer::ParsedPacket parsed;
    uint32_t packet_id = 0;
    
    std::cout << "[Reader] Starting packet processing...\n";
    
    while (!stop_capture_.load() && source->readNextPacket(raw)) {
        // Live capture timeouts yield empty packets; keep polling.
        if (raw.data.empty()) {
            if (source->isLive()) {
                continue;
            }
            break;
        }
        
        // Parse the packet (CapturePacket is layout-compatible with RawPacket)
        PacketAnalyzer::RawPacket raw_pkt;
        raw_pkt.header = raw.header;
        raw_pkt.data = raw.data;
        if (!PacketAnalyzer::PacketParser::parse(raw_pkt, parsed)) {
            continue;  // Skip unparseable packets
        }
        
        // Only process IP packets with TCP/UDP
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
            continue;
        }
        
        // Create packet job
        PacketJob job = createPacketJob(raw, parsed, packet_id++);
        
        // Update global stats
        stats_.total_packets++;
        stats_.total_bytes += raw.data.size();
        
        if (parsed.has_tcp) {
            stats_.tcp_packets++;
        } else if (parsed.has_udp) {
            stats_.udp_packets++;
        }
        
        // Send to appropriate LB based on hash
        LoadBalancer& lb = lb_manager_->getLBForPacket(job.tuple);
        lb.getInputQueue().push(std::move(job));
    }
    
    std::cout << "[Reader] Finished reading " << packet_id << " packets\n";
    reader_finished_ = true;
}

PacketJob DPIEngine::createPacketJob(const CapturePacket& raw,
                                      const PacketAnalyzer::ParsedPacket& parsed,
                                      uint32_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    
    // Set five-tuple - parse IP addresses from string back to uint32
    auto parseIP = [](const std::string& ip) -> uint32_t {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0;
        for (char c : ip) {
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    };
    
    job.tuple.src_ip = parseIP(parsed.src_ip);
    job.tuple.dst_ip = parseIP(parsed.dest_ip);
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;
    
    // TCP flags
    job.tcp_flags = parsed.tcp_flags;
    
    // Copy packet data
    job.data = raw.data;
    
    // Calculate offsets
    job.eth_offset = 0;
    job.ip_offset = 14;  // Ethernet header is 14 bytes
    
    // IP header length
    if (job.data.size() > 14) {
        uint8_t ip_ihl = job.data[14] & 0x0F;
        size_t ip_header_len = ip_ihl * 4;
        job.transport_offset = 14 + ip_header_len;
        
        // Transport header length
        if (parsed.has_tcp && job.data.size() > job.transport_offset) {
            uint8_t tcp_data_offset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
            size_t tcp_header_len = tcp_data_offset * 4;
            job.payload_offset = job.transport_offset + tcp_header_len;
        } else if (parsed.has_udp) {
            job.payload_offset = job.transport_offset + 8;  // UDP header is 8 bytes
        }
        
        if (job.payload_offset < job.data.size()) {
            job.payload_length = job.data.size() - job.payload_offset;
            job.payload_data = job.data.data() + job.payload_offset;
        }
    }
    
    return job;
}

void DPIEngine::outputThreadFunc() {
    while (running_ || !output_queue_.empty()) {
        auto job_opt = output_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (job_opt) {
            writeOutputPacket(*job_opt);
        }
    }
}

void DPIEngine::handleOutput(const PacketJob& job, PacketAction action) {
    if (action == PacketAction::DROP) {
        stats_.dropped_packets++;
        return;
    }
    
    stats_.forwarded_packets++;
    output_queue_.push(job);
}

bool DPIEngine::writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return false;
    
    output_file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return output_file_.good();
}

void DPIEngine::writeOutputPacket(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) return;
    
    // Write packet header
    PacketAnalyzer::PcapPacketHeader pkt_header;
    pkt_header.ts_sec = job.ts_sec;
    pkt_header.ts_usec = job.ts_usec;
    pkt_header.incl_len = job.data.size();
    pkt_header.orig_len = job.data.size();
    
    output_file_.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
    output_file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
}

// ============================================================================
// Rule Management API
// ============================================================================

void DPIEngine::blockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->blockIP(ip);
    }
}

void DPIEngine::unblockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->unblockIP(ip);
    }
}

void DPIEngine::blockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->blockApp(app);
    }
}

void DPIEngine::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            blockApp(static_cast<AppType>(i));
            return;
        }
    }
    std::cerr << "[DPIEngine] Unknown app: " << app_name << "\n";
}

void DPIEngine::unblockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->unblockApp(app);
    }
}

void DPIEngine::unblockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            unblockApp(static_cast<AppType>(i));
            return;
        }
    }
}

void DPIEngine::blockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->blockDomain(domain);
    }
}

void DPIEngine::unblockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->unblockDomain(domain);
    }
}

bool DPIEngine::loadRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->loadRules(filename);
    }
    return false;
}

bool DPIEngine::saveRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->saveRules(filename);
    }
    return false;
}

// ============================================================================
// Reporting
// ============================================================================

std::string DPIEngine::generateReport() const {
    std::ostringstream ss;
    
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                    DPI ENGINE STATISTICS                      ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ PACKET STATISTICS                                             ║\n";
    ss << "║   Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                        ║\n";
    ss << "║   Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                        ║\n";
    ss << "║   TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                        ║\n";
    ss << "║   UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                        ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ FILTERING STATISTICS                                          ║\n";
    ss << "║   Forwarded:          " << std::setw(12) << stats_.forwarded_packets.load() << "                        ║\n";
    ss << "║   Dropped/Blocked:    " << std::setw(12) << stats_.dropped_packets.load() << "                        ║\n";
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        ss << "║   Drop Rate:          " << std::setw(11) << std::fixed << std::setprecision(2) << drop_rate << "%                        ║\n";
    }
    
    if (lb_manager_) {
        auto lb_stats = lb_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ LOAD BALANCER STATISTICS                                      ║\n";
        ss << "║   LB Received:        " << std::setw(12) << lb_stats.total_received << "                        ║\n";
        ss << "║   LB Dispatched:      " << std::setw(12) << lb_stats.total_dispatched << "                        ║\n";
    }
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ FAST PATH STATISTICS                                          ║\n";
        ss << "║   FP Processed:       " << std::setw(12) << fp_stats.total_processed << "                        ║\n";
        ss << "║   FP Forwarded:       " << std::setw(12) << fp_stats.total_forwarded << "                        ║\n";
        ss << "║   FP Dropped:         " << std::setw(12) << fp_stats.total_dropped << "                        ║\n";
        ss << "║   Active Connections: " << std::setw(12) << fp_stats.total_connections << "                        ║\n";
    }
    
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ BLOCKING RULES                                                ║\n";
        ss << "║   Blocked IPs:        " << std::setw(12) << rule_stats.blocked_ips << "                        ║\n";
        ss << "║   Blocked Apps:       " << std::setw(12) << rule_stats.blocked_apps << "                        ║\n";
        ss << "║   Blocked Domains:    " << std::setw(12) << rule_stats.blocked_domains << "                        ║\n";
        ss << "║   Blocked Ports:      " << std::setw(12) << rule_stats.blocked_ports << "                        ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

std::string DPIEngine::generateClassificationReport() const {
    if (fp_manager_) {
        return fp_manager_->generateClassificationReport();
    }
    return "";
}

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

void DPIEngine::printStatus() const {
    std::cout << "\n--- Live Status ---\n";
    std::cout << "Packets: " << stats_.total_packets.load()
              << " | Forwarded: " << stats_.forwarded_packets.load()
              << " | Dropped: " << stats_.dropped_packets.load() << "\n";
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        std::cout << "Connections: " << fp_stats.total_connections << "\n";
    }
}

} // namespace DPI
