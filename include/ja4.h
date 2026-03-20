#ifndef JA4_H
#define JA4_H

#include "tls_parser.h"
#include <string>

bool is_grease(uint16_t value);
std::string build_ja4_fingerprint(const ClientHelloInfo& info);

#endif