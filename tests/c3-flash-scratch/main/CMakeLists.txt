idf_build_get_property(sdk_python PYTHON)
execute_process(
    COMMAND "${sdk_python}" "${CMAKE_CURRENT_LIST_DIR}/../make_fixture.py"
            "${CMAKE_CURRENT_BINARY_DIR}"
    RESULT_VARIABLE fixture_result
    OUTPUT_VARIABLE fixture_output
    ERROR_VARIABLE fixture_error)
if(NOT fixture_result STREQUAL "0")
    message(FATAL_ERROR "C3 Flash fixture generation failed: ${fixture_error}")
endif()
message(STATUS "${fixture_output}")
get_filename_component(efrp_component_dir "${CMAKE_CURRENT_LIST_DIR}/../../.." REALPATH)
get_filename_component(efrp_component_name "${efrp_component_dir}" NAME)
idf_component_register(SRCS "main.c" REQUIRES "${efrp_component_name}" esp_partition esp_timer
    INCLUDE_DIRS "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
