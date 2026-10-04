if(NOT EFRP_NGTCP2_SOURCE_DIR OR NOT EFRP_PICOTLS_SOURCE_DIR)
    message(FATAL_ERROR "QUIC requires explicit pinned EFRP_NGTCP2_SOURCE_DIR and EFRP_PICOTLS_SOURCE_DIR; prepare with tools/quic_sources.py")
endif()
file(READ "${CMAKE_CURRENT_LIST_DIR}/../quic-lock.json" source_lock)
foreach(dependency ngtcp2 picotls)
    string(TOUPPER "${dependency}" upper)
    string(JSON expected_revision GET "${source_lock}" "${dependency}" revision)
    set(source_dir "${EFRP_${upper}_SOURCE_DIR}")
    get_filename_component(source_dir "${source_dir}" REALPATH)
    execute_process(COMMAND git -C "${source_dir}" rev-parse --show-toplevel
        OUTPUT_VARIABLE source_root OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE root_status)
    get_filename_component(source_root "${source_root}" REALPATH)
    execute_process(COMMAND git -C "${source_dir}" rev-parse HEAD OUTPUT_VARIABLE revision
        OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE status)
    execute_process(COMMAND git -C "${source_dir}" status --porcelain --untracked-files=normal
        OUTPUT_VARIABLE dirty OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE dirty_status)
    if(NOT root_status EQUAL 0 OR NOT source_root STREQUAL source_dir OR
        NOT status EQUAL 0 OR NOT revision STREQUAL expected_revision OR NOT dirty_status EQUAL 0 OR dirty)
        message(FATAL_ERROR "${dependency}: clean exact source revision required: ${expected_revision}")
    endif()
endforeach()
