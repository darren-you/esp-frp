// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef enum { SAMPLE_ECHO_NORMAL, SAMPLE_ECHO_LOCAL_FIN, SAMPLE_ECHO_PAUSED } sample_echo_mode_t;
bool sample_echo_start(uint16_t port);
bool sample_echo_arm(sample_echo_mode_t mode);
bool sample_echo_resume(void);
bool sample_echo_reset(void);
void sample_echo_step(void);
void sample_echo_stop(void);
void sample_echo_report(void);
