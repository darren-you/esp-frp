// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stdint.h>
bool sample_udp_echo_start(uint16_t port, uint16_t max_payload);
void sample_udp_echo_clear_pending(void);
void sample_udp_echo_step(void);
bool sample_udp_echo_stop(void);
void sample_udp_echo_report(void);
