#ifndef TLS_PARSER_H
#define TLS_PARSER_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

struct ClientHelloInfo {
    std::string transport = "t";
    std::string tls_version = "00";
    bool has_sni = false;
    std::string server_name;
    std::string alpn = "00";

    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> signature_algorithms;
};

struct ParseResult {
    ClientHelloInfo hello;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
};

std::vector<ParseResult> parse_pcap_for_client_hellos(const std::string& pcap_file);
std::vector<ParseResult> capture_live_client_hellos(const std::string& interface, int max_packets = 50);

#endif