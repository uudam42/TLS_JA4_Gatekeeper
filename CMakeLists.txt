cmake_minimum_required(VERSION 3.16)
project(tls_ja4_gatekeeper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

find_package(OpenSSL REQUIRED)
find_library(PCAP_LIBRARY pcap REQUIRED)

add_executable(tls_gatekeeper
    src/main.cpp
    src/tls_parser.cpp
    src/ja4.cpp
    src/rules.cpp
)

target_link_libraries(tls_gatekeeper
    PRIVATE
    ${PCAP_LIBRARY}
    OpenSSL::Crypto
)