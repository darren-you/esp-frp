if(CMAKE_BUILD_EARLY_EXPANSION)
    idf_component_register(REQUIRES mbedtls lwip)
    return()
endif()
set(prototype "${CMAKE_CURRENT_LIST_DIR}/../..")
set(efrp_source "${prototype}/../../src")
set(ngtcp2 "${EFRP_NGTCP2_SOURCE_DIR}")
set(picotls "${EFRP_PICOTLS_SOURCE_DIR}")
include("${prototype}/../../tools/quic_picotls_sources.cmake")
# The pinned upstream core declares its exact C source set. Consume that set
# without executing upstream package/export/example configuration under IDF.
file(READ "${ngtcp2}/lib/CMakeLists.txt" ngtcp2_cmake)
string(REGEX MATCH "set\\(ngtcp2_SOURCES[^)]*\\)" source_declaration "${ngtcp2_cmake}")
string(REGEX MATCHALL "ngtcp2_[a-z0-9_]+\\.c" ngtcp2_sources "${source_declaration}")
if(NOT ngtcp2_sources)
    message(FATAL_ERROR "Pinned ngtcp2 C source declaration unavailable")
endif()
list(TRANSFORM ngtcp2_sources PREPEND "${ngtcp2}/lib/")
# Upstream's unused ksl diagnostic uses %u for uint32_t. Picolibc typedefs
# uint32_t as unsigned long; retain the diagnostic warning on this unchanged
# third-party source while first-party code keeps IDF's -Werror.
set_source_files_properties("${ngtcp2}/lib/ngtcp2_ksl.c" PROPERTIES COMPILE_OPTIONS "-Wno-error=format")
# Picotls uses valid C partial aggregate initializers (remaining fields zero).
set_source_files_properties("${picotls}/lib/picotls.c" PROPERTIES
    COMPILE_OPTIONS "-Wno-error=missing-field-initializers")
set(PACKAGE_VERSION "1.25.0")
set(PACKAGE_VERSION_NUM "0x011900")
set(HAVE_ARPA_INET_H 1)
set(HAVE_NETINET_IN_H 1)
set(HAVE_UNISTD_H 1)
configure_file("${ngtcp2}/cmakeconfig.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")
configure_file("${ngtcp2}/lib/includes/ngtcp2/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/ngtcp2/version.h" @ONLY)
idf_component_register(SRCS compile_main.c "${prototype}/client.c" "${efrp_source}/quic_crypto.c"
    "${efrp_source}/quic_certificate.c" "${efrp_source}/quic_random.c"
    "${ngtcp2}/crypto/shared.c" ${ngtcp2_sources} ${minicrypto_sources}
    INCLUDE_DIRS "${efrp_source}" "${ngtcp2}/lib/includes" "${ngtcp2}/crypto/includes"
        "${CMAKE_CURRENT_BINARY_DIR}"
    PRIV_INCLUDE_DIRS "${ngtcp2}/lib" "${ngtcp2}/crypto"
        "${picotls}/deps/cifra/src" "${picotls}/deps/cifra/src/ext" "${picotls}/deps/micro-ecc"
    REQUIRES mbedtls lwip)
# Picolibc owns an unrelated picotls.h; normal -I precedence selects the pinned
# TLS library for these sources ahead of the toolchain's system headers.
target_include_directories(${COMPONENT_LIB} PUBLIC "${picotls}/include")
target_compile_definitions(${COMPONENT_LIB} PRIVATE HAVE_CONFIG_H NGTCP2_STATICLIB BUILDING_NGTCP2 PTLS_HAVE_LOG=0)
