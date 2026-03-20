#include "ja4.h"
#include "rules.h"
#include "tls_parser.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void write_csv(const std::string& filename,
                      const std::vector<ParseResult>& results,
                      RuleEngine& engine) {
    std::ofstream out(filename);
    if (!out.is_open()) {
        std::cerr << "[!] Failed to open CSV output file: " << filename << "\n";
        return;
    }

    out << "src_ip,src_port,dst_ip,dst_port,tls_version,has_sni,server_name,alpn,"
           "cipher_count,extension_count,signature_algorithm_count,ja4,decision,rule_reason,risk_level\n";

    for (const auto& r : results) {
        std::string ja4 = build_ja4_fingerprint(r.hello);
        RuleDecision decision = engine.decide(ja4);

        out << r.src_ip << ","
            << r.src_port << ","
            << r.dst_ip << ","
            << r.dst_port << ","
            << r.hello.tls_version << ","
            << (r.hello.has_sni ? "true" : "false") << ","
            << r.hello.server_name << ","
            << r.hello.alpn << ","
            << r.hello.cipher_suites.size() << ","
            << r.hello.extensions.size() << ","
            << r.hello.signature_algorithms.size() << ","
            << ja4 << ","
            << decision.action << ","
            << decision.reason << ","
            << decision.risk_level << "\n";
    }

    std::cout << "[+] CSV exported to: " << filename << "\n";
}

int main(int argc, char* argv[]) {
    bool json_mode = false;
    bool live_mode = false;
    bool csv_mode = false;
    std::string input_target;
    std::string csv_file;

    if (argc == 2) {
        input_target = argv[1];
    } else if (argc == 3 && std::string(argv[1]) == "--json") {
        json_mode = true;
        input_target = argv[2];
    } else if (argc == 3 && std::string(argv[1]) == "--live") {
        live_mode = true;
        input_target = argv[2];
    } else if (argc == 4 && std::string(argv[2]) == "--csv") {
        input_target = argv[1];
        csv_mode = true;
        csv_file = argv[3];
    } else if (argc == 4 && std::string(argv[1]) == "--live" && std::string(argv[3]) == "--json") {
        live_mode = true;
        json_mode = true;
        input_target = argv[2];
    } else if (argc == 4 && std::string(argv[1]) == "--json" && std::string(argv[2]) == "--live") {
        json_mode = true;
        live_mode = true;
        input_target = argv[3];
    } else {
        std::cerr << "Usage:\n";
        std::cerr << "  ./tls_gatekeeper <pcap_file>\n";
        std::cerr << "  ./tls_gatekeeper --json <pcap_file>\n";
        std::cerr << "  ./tls_gatekeeper <pcap_file> --csv <output_file>\n";
        std::cerr << "  ./tls_gatekeeper --live <interface>\n";
        std::cerr << "  ./tls_gatekeeper --live <interface> --json\n";
        return 1;
    }

    std::vector<ParseResult> results;

    if (live_mode) {
        results = capture_live_client_hellos(input_target, 500);
    } else {
        results = parse_pcap_for_client_hellos(input_target);
    }

    if (results.empty()) {
        std::cerr << "[-] No TLS ClientHello found.\n";
        return 1;
    }

    RuleEngine engine;
    engine.load_rules("rules/fingerprints.txt");

    if (csv_mode) {
        write_csv(csv_file, results, engine);
        return 0;
    }

    if (json_mode) {
        std::cout << "[\n";
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            std::string ja4 = build_ja4_fingerprint(r.hello);
            RuleDecision decision = engine.decide(ja4);

            std::cout << "  {\n";
            std::cout << "    \"src_ip\": \"" << r.src_ip << "\",\n";
            std::cout << "    \"src_port\": " << r.src_port << ",\n";
            std::cout << "    \"dst_ip\": \"" << r.dst_ip << "\",\n";
            std::cout << "    \"dst_port\": " << r.dst_port << ",\n";
            std::cout << "    \"tls_version\": \"" << r.hello.tls_version << "\",\n";
            std::cout << "    \"has_sni\": " << (r.hello.has_sni ? "true" : "false") << ",\n";
            std::cout << "    \"server_name\": \"" << r.hello.server_name << "\",\n";
            std::cout << "    \"alpn\": \"" << r.hello.alpn << "\",\n";
            std::cout << "    \"cipher_count\": " << r.hello.cipher_suites.size() << ",\n";
            std::cout << "    \"extension_count\": " << r.hello.extensions.size() << ",\n";
            std::cout << "    \"signature_algorithm_count\": " << r.hello.signature_algorithms.size() << ",\n";
            std::cout << "    \"ja4\": \"" << ja4 << "\",\n";
            std::cout << "    \"decision\": \"" << decision.action << "\",\n";
            std::cout << "    \"rule_reason\": \"" << decision.reason << "\",\n";
            std::cout << "    \"risk_level\": \"" << decision.risk_level << "\"\n";
            std::cout << "  }";

            if (i + 1 < results.size()) {
                std::cout << ",";
            }
            std::cout << "\n";
        }
        std::cout << "]\n";
    } else {
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            std::string ja4 = build_ja4_fingerprint(r.hello);
            RuleDecision decision = engine.decide(ja4);

            std::cout << "Connection #" << (i + 1) << "\n";
            std::cout << "-------------\n";
            std::cout << "Src IP: " << r.src_ip << "\n";
            std::cout << "Src Port: " << r.src_port << "\n";
            std::cout << "Dst IP: " << r.dst_ip << "\n";
            std::cout << "Dst Port: " << r.dst_port << "\n";
            std::cout << "TLS Version: " << r.hello.tls_version << "\n";
            std::cout << "SNI Present: " << (r.hello.has_sni ? "Yes" : "No") << "\n";
            std::cout << "Server Name: " << r.hello.server_name << "\n";
            std::cout << "ALPN: " << r.hello.alpn << "\n";
            std::cout << "Cipher Count: " << r.hello.cipher_suites.size() << "\n";
            std::cout << "Extension Count: " << r.hello.extensions.size() << "\n";
            std::cout << "Signature Algorithm Count: " << r.hello.signature_algorithms.size() << "\n";
            std::cout << "JA4: " << ja4 << "\n";
            std::cout << "Decision: " << decision.action << "\n";
            std::cout << "Rule Reason: " << decision.reason << "\n";
            std::cout << "Risk Level: " << decision.risk_level << "\n";

            if (i + 1 < results.size()) {
                std::cout << "\n";
            }
        }
    }

    return 0;
}
