// SPDX-License-Identifier: Apache-2.0
#include "client_port.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include <stdlib.h>

struct efrp_port {
    StaticSemaphore_t api_storage, status_storage, signal_storage;
    SemaphoreHandle_t api, status, signal;
    StaticQueue_t queue_storage;
    uint8_t commands[EFRP_COMMAND_CAPACITY * sizeof(efrp_command_t)];
    QueueHandle_t queue;
    StaticTask_t task_storage;
    StackType_t *stack;
    TaskHandle_t task;
    void (*entry)(void *);
    void *context;
};
static TickType_t ticks(uint32_t ms)
{
    if (ms == UINT32_MAX) return portMAX_DELAY;
    if (!ms) return 0;
    /* Round up instead of turning sub-tick waits into a busy loop. */
    uint64_t n = ((uint64_t)ms * configTICK_RATE_HZ + 999u) / 1000u;
    return n >= portMAX_DELAY ? portMAX_DELAY - 1 : (TickType_t)n;
}
static void task_entry(void *context)
{
    efrp_port_t *p = context;
    p->entry(p->context);
    /* External join observes suspended before deleting. No task ever resumes
     * this private handle, so stack/TCB are no longer in use when reclaimed. */
    for (;;) vTaskSuspend(NULL);
}
efrp_result_t efrp_port_create(efrp_port_t **out)
{
    efrp_port_t *p = calloc(1, sizeof *p); if (!p) return EFRP_NO_MEMORY;
    p->api = xSemaphoreCreateMutexStatic(&p->api_storage);
    p->status = xSemaphoreCreateMutexStatic(&p->status_storage);
    p->signal = xSemaphoreCreateBinaryStatic(&p->signal_storage);
    p->queue = xQueueCreateStatic(EFRP_COMMAND_CAPACITY, sizeof(efrp_command_t), p->commands, &p->queue_storage);
    p->stack = malloc(EFRP_WORKER_STACK_BYTES);
    if (!p->api || !p->status || !p->signal || !p->queue || !p->stack) {
        efrp_port_destroy(p); return EFRP_NO_MEMORY;
    }
    *out = p; return EFRP_OK;
}
efrp_result_t efrp_port_launch(efrp_port_t *p, void (*entry)(void *), void *context)
{
    p->entry = entry; p->context = context;
    /* IDF stack depth is bytes. Static storage permits synchronous join/free;
     * no idle-task deferred cleanup is used for repeated destroy/create. */
    p->task = xTaskCreateStatic(task_entry, "esp_frp", EFRP_WORKER_STACK_BYTES, p, 5, p->stack, &p->task_storage);
    return p->task ? EFRP_OK : EFRP_NO_MEMORY;
}
bool efrp_port_is_worker(efrp_port_t *p) { return p->task && xTaskGetCurrentTaskHandle() == p->task; }
bool efrp_port_api_lock(efrp_port_t *p) { return xSemaphoreTake(p->api, 0) == pdTRUE; }
void efrp_port_api_unlock(efrp_port_t *p) { xSemaphoreGive(p->api); }
void efrp_port_status_lock(efrp_port_t *p) { xSemaphoreTake(p->status, portMAX_DELAY); }
void efrp_port_status_unlock(efrp_port_t *p) { xSemaphoreGive(p->status); }
bool efrp_port_send(efrp_port_t *p, efrp_command_t command) { return xQueueSend(p->queue, &command, 0) == pdTRUE; }
bool efrp_port_receive(efrp_port_t *p, efrp_command_t *command, uint32_t ms) { return xQueueReceive(p->queue, command, ticks(ms)) == pdTRUE; }
void efrp_port_signal(efrp_port_t *p) { xSemaphoreGive(p->signal); }
void efrp_port_wait(efrp_port_t *p, uint32_t ms) { xSemaphoreTake(p->signal, ticks(ms)); }
uint64_t efrp_port_now_ms(void) { return (uint64_t)esp_timer_get_time() / 1000u; }
void efrp_port_destroy(efrp_port_t *p)
{
    if (!p) return;
    if (p->task) {
        while (eTaskGetState(p->task) != eSuspended) vTaskDelay(1);
        vTaskDelete(p->task);
    }
    free(p->stack);
    if (p->queue) vQueueDelete(p->queue);
    if (p->signal) vSemaphoreDelete(p->signal);
    if (p->status) vSemaphoreDelete(p->status);
    if (p->api) vSemaphoreDelete(p->api);
    free(p);
}
