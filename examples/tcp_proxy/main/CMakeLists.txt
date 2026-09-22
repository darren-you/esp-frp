idf_component_register(SRCS "sample_main.c" "sample_echo.c" "sample_resources.c"
    INCLUDE_DIRS "." "${CMAKE_CURRENT_BINARY_DIR}"
    REQUIRES esp-frp esp_wifi esp_event esp_netif esp_timer esp_driver_usb_serial_jtag lwip)
if(NOT EFRP_SAMPLE_INPUTS)
    set(EFRP_SAMPLE_INPUTS "${CMAKE_CURRENT_LIST_DIR}/../inputs.example.h")
endif()
if(NOT EXISTS "${EFRP_SAMPLE_INPUTS}" OR IS_DIRECTORY "${EFRP_SAMPLE_INPUTS}")
    message(FATAL_ERROR "EFRP_SAMPLE_INPUTS must name an existing header")
endif()
configure_file("${EFRP_SAMPLE_INPUTS}" "${CMAKE_CURRENT_BINARY_DIR}/sample_inputs.h" COPYONLY)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
