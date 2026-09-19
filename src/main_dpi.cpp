#include <csignal>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "dpi_engine.h"
#include "rules_store.h"
#include "capture_source.h"

using namespace DPI;

namespace {

// Set from the Ctrl+C handler so DPIEngine can stop live capture cleanly.
DPIEngine* g_engine = nullptr;

void onSignal(int) {
    if (g_engine) {
        g_engine->stopCapture();
    }
}

void printUsage(const char* program) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v2.0                            ║
║         Deep Packet Inspection - Live Capture + Rules         ║
╚══════════════════════════════════════════════════════════════╝

Usage: )" << program << R"( <input.pcap> <output.pcap> [options]
       )" << program << R"( -i <interface> [-o output.pcap] [options]

Modes:
  <input.pcap> <output.pcap>   Process a saved PCAP file
  -i <interface>               Capture live traffic from an interface
                               (-l lists available interfaces)

Options:
  --rules <file>          Load persistent JSON rules from file
  --block-ip <ip>         Block packets from source IP
  --block-app <app>       Block application (e.g., YouTube, Facebook)
  --block-domain <dom>    Block domain (supports wildcards: *.facebook.com)
  --export-stats [port]   Stream live JSON events to dashboard IPC port (default: 9000)
  --ipc-host <host>       Dashboard IPC host (default: 127.0.0.1)
  --ipc-port <port>       Dashboard IPC port (default: 9000)
  -o <file>               Output PCAP for forwarded traffic (live mode)
  --lbs <n>               Number of load balancer threads (default: 2)
  --fps <n>               FP threads per LB (default: 2)
  -l, --list-interfaces   List available capture interfaces and exit
  --verbose               Enable verbose output

Examples:
  )" << program << R"( capture.pcap filtered.pcap
  )" << program << R"( -i eth0 -o live.pcap --rules rules.json --export-stats 9000
  )" << program << R"( -l
  )" << program << R"( capture.pcap filtered.pcap --block-app YouTube --rules rules.json
)";
}

} // namespace

int main(int argc, char* argv[]) {
    bool list_only = false;
    std::string input_file;
    std::string output_file;
    std::string live_interface;
    std::string rules_store_path;

    // Parse the full argv once.
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-l" || arg == "--list-interfaces") {
            list_only = true;
        } else if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            live_interface = argv[++i];
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_store_path = argv[++i];
        }
    }

    // List available interfaces first (no engine needed).
    if (list_only) {
        auto ifaces = LiveCapture::listInterfaces();
        std::cout << "Available capture interfaces:\n";
        for (const auto& name : ifaces) {
            std::cout << "  " << name << "\n";
        }
        if (ifaces.empty()) {
            std::cout << "  (none - built without libpcap or no interfaces found)\n";
        }
        return 0;
    }

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
        printUsage(argv[0]);
        return 0;
    }

    if (live_interface.empty() && (argc < 3 || argv[1][0] == '-')) {
        printUsage(argv[0]);
        return 1;
    }

    // Positional args: file mode uses argv[1]/argv[2].
    if (live_interface.empty()) {
        input_file = argv[1];
        output_file = argv[2];
    }

    DPIEngine::Config config;
    config.num_load_balancers = 2;
    config.fps_per_lb = 2;

    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;

    for (int i = (live_interface.empty() ? 3 : 1); i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            block_ips.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            block_apps.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            block_domains.push_back(argv[++i]);
        } else if (arg == "--export-stats" || arg == "--ipc") {
            config.enable_ipc = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                try {
                    config.ipc_port = static_cast<uint16_t>(std::stoi(argv[++i]));
                } catch (...) {}
            }
        } else if (arg == "--ipc-host" && i + 1 < argc) {
            config.ipc_host = argv[++i];
            config.enable_ipc = true;
        } else if (arg == "--ipc-port" && i + 1 < argc) {
            config.ipc_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            config.enable_ipc = true;
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_store_path = argv[++i];
        } else if (arg == "--lbs" && i + 1 < argc) {
            config.num_load_balancers = std::stoi(argv[++i]);
        } else if (arg == "--fps" && i + 1 < argc) {
            config.fps_per_lb = std::stoi(argv[++i]);
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        }
    }

    // Create DPI engine
    DPIEngine engine(config);
    g_engine = &engine;

    // Initialize
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }

    // Persistent rules first (they may supply blocking rules).
    if (!rules_store_path.empty()) {
        RulesStore store;
        std::string error;
        if (!store.load(rules_store_path, error)) {
            std::cerr << "[main] " << error << "\n";
            return 1;
        }
        if (!store.applyTo(engine.getRuleManager(), error)) {
            std::cerr << "[main] Failed to apply rules: " << error << "\n";
            return 1;
        }
        std::cout << "[main] Applied " << store.size()
                  << " persistent rules from " << rules_store_path << "\n";
    }

    // Apply command-line blocking rules
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& domain : block_domains) engine.blockDomain(domain);

    // Install Ctrl+C handler for live capture stop.
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    bool ok;
    if (!live_interface.empty()) {
        ok = engine.processLive(live_interface, output_file);
    } else {
        ok = engine.processFile(input_file, output_file);
    }

    g_engine = nullptr;
    return ok ? 0 : 1;
}