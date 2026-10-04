// SPDX-License-Identifier: Apache-2.0
#pragma once
typedef enum { QUIC_FIXTURE_SEND_NORMAL, QUIC_FIXTURE_SEND_BLOCK, QUIC_FIXTURE_SEND_FAIL } quic_fixture_send_mode_t;
void quic_fixture_send_mode(quic_fixture_send_mode_t mode);
unsigned quic_fixture_send_attempts(void);
