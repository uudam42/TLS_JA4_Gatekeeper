#include "tls_parser.h"
#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>

static constexpr bool DEBUG_LIVE = false;
static constexpr int DEBUG_LIMIT = 40;

static uint16_t read_u16(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

static uint32_t read_u24(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8)  |
           data[2];
}

static std::string ip_to_string(const uint8_t* data, bool is_ipv6) {
    char buffer[INET6_ADDRSTRLEN] = {0};

    if (is_ipv6) {
        inet_ntop(AF_INET6, data, buffer, sizeof(buffer));
    } else {
        inet_ntop(AF_INET, data, buffer, sizeof(buffer));
    }

    return std::string(buffer);
}

static bool parse_tls_extensions(const uint8_t* ext_data, size_t ext_len, ClientHelloInfo& info) {
    size_t offset = 0;

    while (offset + 4 <= ext_len) {
        uint16_t ext_type = read_u16(ext_data + offset);
        uint16_t ext_size = read_u16(ext_data + offset + 2);
        offset += 4;

        if (offset + ext_size > ext_len) {
            return false;
        }

        info.extensions.push_back(ext_type);
        const uint8_t* body = ext_data + offset;

        // SNI
        if (ext_type == 0x0000) {
            if (ext_size >= 2) {
                size_t sni_offset = 2; // skip server_name_list length
                while (sni_offset + 3 <= ext_size) {
                    uint8_t name_type = body[sni_offset];
                    uint16_t name_len = read_u16(body + sni_offset + 1);
                    sni_offset += 3;

                    if (sni_offset + name_len > ext_size) {
                        return false;
                    }

                    if (name_type == 0x00) {
                        info.has_sni = true;
                        info.server_name.assign(
                            reinterpret_cast<const char*>(body + sni_offset),
                            name_len
                        );
                        break;
                    }

                    sni_offset += name_len;
                }
            }
        }
        // signature_algorithms
        else if (ext_type == 0x000d) {
            if (ext_size >= 2) {
                uint16_t sig_list_len = read_u16(body);
                if (2 + sig_list_len <= ext_size) {
                    for (size_t i = 0; i + 1 < sig_list_len; i += 2) {
                        info.signature_algorithms.push_back(read_u16(body + 2 + i));
                    }
                }
            }
        }
        // ALPN
        else if (ext_type == 0x0010) {
            if (ext_size >= 2) {
                uint16_t alpn_list_len = read_u16(body);
                if (2 + alpn_list_len <= ext_size && alpn_list_len >= 1) {
                    size_t p = 2;
                    while (p < 2 + alpn_list_len && p < ext_size) {
                        uint8_t proto_len = body[p];
                        p += 1;
                        if (p + proto_len <= ext_size) {
                            std::string proto(reinterpret_cast<const char*>(body + p), proto_len);
                            if (info.alpn == "00") {
                                if (proto == "h2") info.alpn = "h2";
                                else if (proto == "http/1.1") info.alpn = "h1";
                            }
                        }
                        p += proto_len;
                    }
                }
            }
        }
        // supported_versions
        else if (ext_type == 0x002b) {
            if (ext_size >= 3) {
                uint8_t versions_len = body[0];
                if (1 + versions_len <= ext_size && versions_len >= 2) {
                    for (size_t i = 0; i + 1 < versions_len; i += 2) {
                        uint16_t v = read_u16(body + 1 + i);
                        if (v == 0x0304) {
                            info.tls_version = "13";
                            break;
                        } else if (v == 0x0303) {
                            info.tls_version = "12";
                        } else if (v == 0x0302) {
                            info.tls_version = "11";
                        } else if (v == 0x0301) {
                            info.tls_version = "10";
                        }
                    }
                }
            }
        }

        offset += ext_size;
    }

    return true;
}

static bool parse_client_hello(const uint8_t* data, size_t len, ClientHelloInfo& info) {
    if (len < 42) return false;

    size_t offset = 0;

    uint16_t legacy_version = read_u16(data + offset);
    offset += 2;

    if (legacy_version == 0x0304) info.tls_version = "13";
    else if (legacy_version == 0x0303) info.tls_version = "12";
    else if (legacy_version == 0x0302) info.tls_version = "11";
    else if (legacy_version == 0x0301) info.tls_version = "10";

    // random
    offset += 32;
    if (offset >= len) return false;

    // session id
    uint8_t session_id_len = data[offset];
    offset += 1;
    if (offset + session_id_len > len) return false;
    offset += session_id_len;

    // cipher suites
    if (offset + 2 > len) return false;
    uint16_t cipher_len = read_u16(data + offset);
    offset += 2;
    if (offset + cipher_len > len || cipher_len % 2 != 0) return false;

    for (size_t i = 0; i < cipher_len; i += 2) {
        info.cipher_suites.push_back(read_u16(data + offset + i));
    }
    offset += cipher_len;

    // compression methods
    if (offset + 1 > len) return false;
    uint8_t comp_len = data[offset];
    offset += 1;
    if (offset + comp_len > len) return false;
    offset += comp_len;

    // extensions (optional)
    if (offset + 2 > len) {
        return true;
    }

    uint16_t ext_len = read_u16(data + offset);
    offset += 2;
    if (offset + ext_len > len) return false;

    return parse_tls_extensions(data + offset, ext_len, info);
}

static bool advance_ipv6_headers(
    const uint8_t* packet,
    size_t caplen,
    size_t l3_offset,
    size_t& transport_offset,
    std::string& src_ip,
    std::string& dst_ip
) {
    // IPv6 base header is 40 bytes
    if (caplen < l3_offset + 40) return false;

    src_ip = ip_to_string(packet + l3_offset + 8, true);
    dst_ip = ip_to_string(packet + l3_offset + 24, true);

    uint8_t next_header = packet[l3_offset + 6];
    size_t offset = l3_offset + 40;

    // Skip a few common extension headers
    while (true) {
        if (next_header == 6) { // TCP
            transport_offset = offset;
            return true;
        }

        // Hop-by-Hop, Routing, Destination Options
        if (next_header == 0 || next_header == 43 || next_header == 60) {
            if (caplen < offset + 2) return false;
            uint8_t hdr_ext_len = packet[offset + 1];
            size_t ext_len = static_cast<size_t>(hdr_ext_len + 1) * 8;
            next_header = packet[offset];
            offset += ext_len;
            if (caplen < offset) return false;
            continue;
        }

        // Fragment header
        if (next_header == 44) {
            if (caplen < offset + 8) return false;
            next_header = packet[offset];
            offset += 8;
            if (caplen < offset) return false;
            continue;
        }

        return false;
    }
}

static bool try_parse_tls_from_payload(
    const uint8_t* payload,
    size_t payload_len,
    const std::string& src_ip,
    const std::string& dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    std::vector<ParseResult>& results,
    int& dbg_count
) {
    if (payload_len < 9) return false;

    // Scan through payload instead of assuming TLS starts at offset 0
    for (size_t start = 0; start + 9 <= payload_len; ++start) {
        uint8_t content_type = payload[start];

        if (content_type != 22) { // TLS Handshake
            continue;
        }

        // Basic TLS version sanity
        uint8_t ver_major = payload[start + 1];
        uint8_t ver_minor = payload[start + 2];
        if (ver_major != 0x03) {
            continue;
        }
        if (!(ver_minor == 0x01 || ver_minor == 0x02 || ver_minor == 0x03 || ver_minor == 0x04)) {
            continue;
        }

        uint16_t record_len = read_u16(payload + start + 3);
        if (start + 5 + record_len > payload_len) {
            if (DEBUG_LIVE && dbg_count < DEBUG_LIMIT) {
                std::cout << "[PROC] candidate TLS record spans multiple packets"
                          << " start=" << start
                          << " record_len=" << record_len
                          << " payload_len=" << payload_len << "\n";
                dbg_count++;
            }
            continue;
        }

        const uint8_t* hs = payload + start + 5;
        size_t hs_len_total = record_len;
        if (hs_len_total < 4) continue;

        uint8_t handshake_type = hs[0];
        if (handshake_type != 1) { // ClientHello
            continue;
        }

        uint32_t handshake_len = read_u24(hs + 1);
        if (4 + handshake_len > hs_len_total) continue;

        const uint8_t* client_hello = hs + 4;
        size_t client_hello_len = handshake_len;

        ClientHelloInfo info;
        if (parse_client_hello(client_hello, client_hello_len, info)) {
            ParseResult result;
            result.hello = info;
            result.src_ip = src_ip;
            result.dst_ip = dst_ip;
            result.src_port = src_port;
            result.dst_port = dst_port;
            results.push_back(result);

            if (DEBUG_LIVE && dbg_count < DEBUG_LIMIT) {
                std::cout << "[PROC] success: ClientHello matched"
                          << " src=" << src_ip << ":" << src_port
                          << " dst=" << dst_ip << ":" << dst_port
                          << " sni=" << info.server_name << "\n";
                dbg_count++;
            }
            return true;
        }
    }

    return false;
}

static void process_packet(const struct pcap_pkthdr* header, const u_char* packet, std::vector<ParseResult>& results) {
    static int dbg_count = 0;

    if (header->caplen < 14) return;

    uint16_t ether_type = read_u16(packet + 12);

    size_t l3_offset = 14;
    size_t tcp_offset = 0;
    std::string src_ip;
    std::string dst_ip;
    bool tcp_found = false;

    // IPv4
    if (ether_type == 0x0800) {
        if (header->caplen < l3_offset + 20) return;

        uint8_t version_ihl = packet[l3_offset];
        uint8_t ip_version = version_ihl >> 4;
        uint8_t ihl = version_ihl & 0x0F;
        if (ip_version != 4) return;

        size_t ip_header_len = ihl * 4;
        if (ip_header_len < 20) return;
        if (header->caplen < l3_offset + ip_header_len) return;

        uint8_t protocol = packet[l3_offset + 9];
        if (protocol != 6) return;

        src_ip = ip_to_string(packet + l3_offset + 12, false);
        dst_ip = ip_to_string(packet + l3_offset + 16, false);

        tcp_offset = l3_offset + ip_header_len;
        tcp_found = true;
    }
    // IPv6
    else if (ether_type == 0x86dd) {
        if (!advance_ipv6_headers(packet, header->caplen, l3_offset, tcp_offset, src_ip, dst_ip)) {
            if (DEBUG_LIVE && dbg_count < DEBUG_LIMIT) {
                std::cout << "[PROC] drop: unsupported IPv6 extension header chain\n";
                dbg_count++;
            }
            return;
        }
        tcp_found = true;
    } else {
        if (DEBUG_LIVE && dbg_count < DEBUG_LIMIT) {
            std::cout << "[PROC] drop: unsupported ether_type=0x"
                      << std::hex << ether_type << std::dec << "\n";
            dbg_count++;
        }
        return;
    }

    if (!tcp_found) return;
    if (header->caplen < tcp_offset + 20) return;

    uint16_t src_port = read_u16(packet + tcp_offset);
    uint16_t dst_port = read_u16(packet + tcp_offset + 2);

    uint8_t data_offset_byte = packet[tcp_offset + 12];
    size_t tcp_header_len = ((data_offset_byte >> 4) & 0x0F) * 4;
    if (tcp_header_len < 20) return;
    if (header->caplen < tcp_offset + tcp_header_len) return;

    size_t payload_offset = tcp_offset + tcp_header_len;
    if (header->caplen <= payload_offset) return;

    const uint8_t* payload = packet + payload_offset;
    size_t payload_len = header->caplen - payload_offset;

    if (DEBUG_LIVE && dbg_count < DEBUG_LIMIT) {
        std::cout << "[PROC] payload"
                  << " src=" << src_ip << ":" << src_port
                  << " dst=" << dst_ip << ":" << dst_port
                  << " len=" << payload_len
                  << " first=0x" << std::hex << (int)payload[0] << std::dec
                  << "\n";
        dbg_count++;
    }

    try_parse_tls_from_payload(payload, payload_len, src_ip, dst_ip, src_port, dst_port, results, dbg_count);
}

std::vector<ParseResult> parse_pcap_for_client_hellos(const std::string& pcap_file) {
    std::vector<ParseResult> results;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_file.c_str(), errbuf);

    if (!handle) {
        std::cerr << "[!] Warning: pcap_open_offline failed: " << errbuf << "\n";
        return results;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int ret;

    while ((ret = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (ret == 0) continue;
        process_packet(header, packet, results);
    }

    pcap_close(handle);
    return results;
}

std::vector<ParseResult> capture_live_client_hellos(const std::string& interface, int max_packets) {
    std::vector<ParseResult> results;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "[!] Warning: pcap_open_live failed: " << errbuf << "\n";
        return results;
    }

    struct bpf_program fp;
    const char filter_exp[] = "tcp dst port 443";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[!] Failed to compile filter: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return results;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[!] Failed to set filter: " << pcap_geterr(handle) << "\n";
        pcap_freecode(&fp);
        pcap_close(handle);
        return results;
    }

    pcap_freecode(&fp);

    std::cout << "[+] Live capture started on interface: " << interface << "\n";
    std::cout << "[+] Waiting for TLS ClientHello packets...\n";

    for (int i = 0; i < max_packets; ++i) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int ret = pcap_next_ex(handle, &header, &packet);

        if (ret == 1) {
            if (DEBUG_LIVE) {
                std::cout << "[LIVE] packet captured, len=" << header->caplen << "\n";
            }

            size_t before = results.size();
            process_packet(header, packet, results);

            if (results.size() > before) {
                std::cout << "[+] ClientHello captured in live mode.\n";
                break;
            }
        } else if (ret == 0) {
            continue;
        } else {
            break;
        }
    }

    pcap_close(handle);
    return results;
}