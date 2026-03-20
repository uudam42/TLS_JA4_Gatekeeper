#include "ja4.h"
#include <algorithm>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>
#include <vector>

bool is_grease(uint16_t value) {
    return ((value & 0x0f0f) == 0x0a0a) && (((value >> 8) & 0xff) == (value & 0xff));
}

static std::string to_hex_truncated_sha256(const std::string& input, size_t hex_len = 12) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str().substr(0, hex_len);
}

static std::string two_digit(size_t n) {
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << n;
    return oss.str();
}

static std::string join_sorted_hex_filtered(const std::vector<uint16_t>& values) {
    std::vector<uint16_t> filtered;
    for (auto v : values) {
        if (!is_grease(v)) {
            filtered.push_back(v);
        }
    }

    std::sort(filtered.begin(), filtered.end());

    std::ostringstream oss;
    for (size_t i = 0; i < filtered.size(); ++i) {
        if (i > 0) oss << ",";
        oss << std::hex << std::setw(4) << std::setfill('0') << filtered[i];
    }
    return oss.str();
}

std::string build_ja4_fingerprint(const ClientHelloInfo& info) {
    std::vector<uint16_t> clean_ciphers;
    for (auto c : info.cipher_suites) {
        if (!is_grease(c)) clean_ciphers.push_back(c);
    }

    std::vector<uint16_t> clean_exts;
    for (auto e : info.extensions) {
        if (!is_grease(e)) clean_exts.push_back(e);
    }

    std::string a = info.transport
                  + info.tls_version
                  + (info.has_sni ? "d" : "i")
                  + two_digit(clean_ciphers.size())
                  + two_digit(clean_exts.size())
                  + info.alpn;

    std::string cipher_str = join_sorted_hex_filtered(info.cipher_suites);
    std::string ext_str = join_sorted_hex_filtered(info.extensions);
    std::string sigalg_str = join_sorted_hex_filtered(info.signature_algorithms);

    std::string b = to_hex_truncated_sha256(cipher_str, 12);
    std::string c = to_hex_truncated_sha256(ext_str + "|" + sigalg_str, 12);

    return a + "_" + b + "_" + c;
}