# SPDX-License-Identifier: Apache-2.0
# Fixed C-only QUIC dependencies. Runtime never consumes test-owned source.
set(EFRP_NGTCP2_SOURCE_DIR "" CACHE PATH "Clean checkout pinned by quic-lock.json")
set(EFRP_PICOTLS_SOURCE_DIR "" CACHE PATH "Clean checkout pinned by quic-lock.json")
include("${CMAKE_CURRENT_LIST_DIR}/quic_source_guard.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/quic_picotls_sources.cmake")
set(efrp_quic_source "${CMAKE_CURRENT_LIST_DIR}/../src")
set(efrp_quic_crypto_sources "${efrp_quic_source}/quic_crypto.c"
    "${efrp_quic_source}/quic_certificate.c" "${efrp_quic_source}/quic_peer_security.c"
    "${efrp_quic_source}/quic_random.c"
    "${EFRP_NGTCP2_SOURCE_DIR}/crypto/shared.c")
if(EFRP_QUIC_IDF)
    file(READ "${EFRP_NGTCP2_SOURCE_DIR}/lib/CMakeLists.txt" ngtcp2_cmake)
    string(REGEX MATCH "set\\(ngtcp2_SOURCES[^)]*\\)" source_declaration "${ngtcp2_cmake}")
    string(REGEX MATCHALL "ngtcp2_[a-z0-9_]+\\.c" ngtcp2_sources "${source_declaration}")
    if(NOT ngtcp2_sources)
        message(FATAL_ERROR "Pinned ngtcp2 core source declaration unavailable")
    endif()
    list(TRANSFORM ngtcp2_sources PREPEND "${EFRP_NGTCP2_SOURCE_DIR}/lib/")
    file(READ "${CMAKE_CURRENT_LIST_DIR}/../quic-lock.json" source_lock)
    string(JSON PACKAGE_VERSION GET "${source_lock}" ngtcp2 version)
    string(REPLACE "." ";" version_parts "${PACKAGE_VERSION}")
    list(GET version_parts 0 version_major)
    list(GET version_parts 1 version_minor)
    list(GET version_parts 2 version_patch)
    math(EXPR PACKAGE_VERSION_NUM "(${version_major} << 16) | (${version_minor} << 8) | ${version_patch}" OUTPUT_FORMAT HEXADECIMAL)
    set(HAVE_ARPA_INET_H 1)
    set(HAVE_NETINET_IN_H 1)
    set(HAVE_UNISTD_H 1)
    configure_file("${EFRP_NGTCP2_SOURCE_DIR}/cmakeconfig.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")
    configure_file("${EFRP_NGTCP2_SOURCE_DIR}/lib/includes/ngtcp2/version.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/ngtcp2/version.h" @ONLY)
    # Exact upstream sources retain warnings for these two diagnostics.
    set_source_files_properties("${EFRP_NGTCP2_SOURCE_DIR}/lib/ngtcp2_ksl.c" PROPERTIES
        COMPILE_OPTIONS "-Wno-error=format")
    set_source_files_properties("${EFRP_PICOTLS_SOURCE_DIR}/lib/picotls.c" PROPERTIES
        COMPILE_OPTIONS "-Wno-error=missing-field-initializers")
    set(efrp_quic_sources ${efrp_quic_crypto_sources} ${ngtcp2_sources} ${minicrypto_sources})
else()
    set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
    set(ENABLE_OPENSSL OFF CACHE BOOL "" FORCE)
    set(ENABLE_PICOTLS OFF CACHE BOOL "" FORCE)
    set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
    set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
    # Scope upstream's tests to its own configure; preserve this repo's gate.
    set(efrp_saved_build_testing "${BUILD_TESTING}")
    set(BUILD_TESTING OFF)
    add_subdirectory("${EFRP_NGTCP2_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/ngtcp2")
    set(BUILD_TESTING "${efrp_saved_build_testing}" CACHE BOOL "Build ESP FRP tests" FORCE)
    set(BUILD_TESTING "${efrp_saved_build_testing}")
    add_library(efrp_quic_crypto STATIC ${efrp_quic_crypto_sources} ${minicrypto_sources})
    set_source_files_properties(${efrp_quic_crypto_sources} PROPERTIES
        COMPILE_OPTIONS "-Wall;-Wextra;-Werror;-Wconversion")
    target_include_directories(efrp_quic_crypto PUBLIC "${efrp_quic_source}"
        "${EFRP_NGTCP2_SOURCE_DIR}/crypto/includes"
        PRIVATE "${efrp_quic_source}/../include" "${EFRP_NGTCP2_SOURCE_DIR}/lib" "${EFRP_NGTCP2_SOURCE_DIR}/crypto"
        "${CMAKE_CURRENT_BINARY_DIR}/ngtcp2" "${EFRP_PICOTLS_SOURCE_DIR}/deps/cifra/src"
        "${EFRP_PICOTLS_SOURCE_DIR}/deps/cifra/src/ext" "${EFRP_PICOTLS_SOURCE_DIR}/deps/micro-ecc")
    target_include_directories(efrp_quic_crypto SYSTEM PUBLIC "${EFRP_PICOTLS_SOURCE_DIR}/include")
    target_compile_definitions(efrp_quic_crypto PRIVATE HAVE_CONFIG_H NGTCP2_STATICLIB PTLS_HAVE_LOG=0)
    target_link_libraries(efrp_quic_crypto PUBLIC ngtcp2_static MbedTLS::mbedx509 TF-PSA-Crypto::tfpsacrypto)
    set(efrp_quic_sources "")
endif()
