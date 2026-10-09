if(NOT EFRP_NGTCP2_SOURCE_DIR OR NOT EFRP_PICOTLS_SOURCE_DIR)
    message(FATAL_ERROR "QUIC requires explicit pinned EFRP_NGTCP2_SOURCE_DIR and EFRP_PICOTLS_SOURCE_DIR; prepare with tools/quic_sources.py")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(source_check_args check --quiet --ngtcp2-path "${EFRP_NGTCP2_SOURCE_DIR}"
    --picotls-path "${EFRP_PICOTLS_SOURCE_DIR}")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/quic_sources.py"
    ${source_check_args} RESULT_VARIABLE source_check_status ERROR_VARIABLE source_check_error)
if(NOT source_check_status EQUAL 0)
    message(FATAL_ERROR "Exact complete QUIC/host source required: ${source_check_error}")
endif()
