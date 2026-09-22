// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stdint.h>
bool sample_echo_start(uint16_t port);
void sample_echo_step(void);
void sample_echo_stop(void);
void sample_echo_report(void);
