// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "esp_frp_types.h"
#include <stdbool.h>
#include <stdint.h>
#define EFRP_COMMAND_CAPACITY 4u
#define EFRP_WORKER_STACK_BYTES 6144u
typedef struct efrp_port efrp_port_t;
typedef enum { EFRP_COMMAND_START, EFRP_COMMAND_STOP, EFRP_COMMAND_EXIT } efrp_command_kind_t;
typedef struct { efrp_command_kind_t kind; uint64_t ticket; } efrp_command_t;
efrp_result_t efrp_port_create(efrp_port_t **out);
efrp_result_t efrp_port_launch(efrp_port_t *port, void (*entry)(void *), void *context);
bool efrp_port_is_worker(efrp_port_t *port);
bool efrp_port_api_lock(efrp_port_t *port);
void efrp_port_api_unlock(efrp_port_t *port);
void efrp_port_status_lock(efrp_port_t *port);
void efrp_port_status_unlock(efrp_port_t *port);
bool efrp_port_send(efrp_port_t *port, efrp_command_t command);
bool efrp_port_receive(efrp_port_t *port, efrp_command_t *command, uint32_t wait_ms);
void efrp_port_signal(efrp_port_t *port);
void efrp_port_wait(efrp_port_t *port, uint32_t wait_ms);
uint64_t efrp_port_now_ms(void);
/* Only after EXIT, or failed launch. Joins the task before freeing its storage. */
void efrp_port_destroy(efrp_port_t *port);
