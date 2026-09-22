// SPDX-License-Identifier: Apache-2.0
/* Only the worker test scheduling adapter; not a public POSIX FRPC runtime. */
#define _POSIX_C_SOURCE 200809L
#include "client_port.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
struct efrp_port {
    pthread_mutex_t api, status, lock;
    pthread_cond_t changed, signalled;
    pthread_t thread;
    bool launched, signal;
    efrp_command_t commands[EFRP_COMMAND_CAPACITY];
    unsigned head, used;
    void (*entry)(void *);
    void *context;
};
static struct timespec deadline(uint32_t ms)
{
    struct timespec t; assert(clock_gettime(CLOCK_REALTIME, &t) == 0);
    t.tv_sec += (time_t)(ms / 1000u); t.tv_nsec += (long)(ms % 1000u) * 1000000L;
    if (t.tv_nsec >= 1000000000L) { ++t.tv_sec; t.tv_nsec -= 1000000000L; }
    return t;
}
static void *thread_entry(void *context)
{
    efrp_port_t *p = context; p->entry(p->context); return NULL;
}
efrp_result_t efrp_port_create(efrp_port_t **out)
{
    efrp_port_t *p = calloc(1, sizeof *p); if (!p) return EFRP_NO_MEMORY;
    assert(pthread_mutex_init(&p->api, NULL) == 0);
    assert(pthread_mutex_init(&p->status, NULL) == 0);
    assert(pthread_mutex_init(&p->lock, NULL) == 0);
    assert(pthread_cond_init(&p->changed, NULL) == 0);
    assert(pthread_cond_init(&p->signalled, NULL) == 0);
    *out = p; return EFRP_OK;
}
efrp_result_t efrp_port_launch(efrp_port_t *p, void (*entry)(void *), void *context)
{
    p->entry = entry; p->context = context;
    if (pthread_create(&p->thread, NULL, thread_entry, p) != 0) return EFRP_NO_MEMORY;
    p->launched = true; return EFRP_OK;
}
bool efrp_port_is_worker(efrp_port_t *p) { return p->launched && pthread_equal(pthread_self(), p->thread); }
bool efrp_port_api_lock(efrp_port_t *p) { return pthread_mutex_trylock(&p->api) == 0; }
void efrp_port_api_unlock(efrp_port_t *p) { assert(pthread_mutex_unlock(&p->api) == 0); }
void efrp_port_status_lock(efrp_port_t *p) { assert(pthread_mutex_lock(&p->status) == 0); }
void efrp_port_status_unlock(efrp_port_t *p) { assert(pthread_mutex_unlock(&p->status) == 0); }
bool efrp_port_send(efrp_port_t *p, efrp_command_t command)
{
    assert(pthread_mutex_lock(&p->lock) == 0); bool ok = p->used < EFRP_COMMAND_CAPACITY;
    if (ok) { p->commands[(p->head + p->used++) % EFRP_COMMAND_CAPACITY] = command; pthread_cond_signal(&p->changed); }
    assert(pthread_mutex_unlock(&p->lock) == 0); return ok;
}
bool efrp_port_receive(efrp_port_t *p, efrp_command_t *command, uint32_t ms)
{
    struct timespec end = deadline(ms);
    assert(pthread_mutex_lock(&p->lock) == 0);
    while (!p->used && ms) {
        int rc = ms == UINT32_MAX ? pthread_cond_wait(&p->changed, &p->lock) : pthread_cond_timedwait(&p->changed, &p->lock, &end);
        if (rc == ETIMEDOUT) break;
        assert(rc == 0);
    }
    bool ok = p->used != 0;
    if (ok) { *command = p->commands[p->head++]; p->head %= EFRP_COMMAND_CAPACITY; --p->used; }
    assert(pthread_mutex_unlock(&p->lock) == 0); return ok;
}
void efrp_port_signal(efrp_port_t *p)
{
    assert(pthread_mutex_lock(&p->lock) == 0); p->signal = true; pthread_cond_signal(&p->signalled);
    assert(pthread_mutex_unlock(&p->lock) == 0);
}
void efrp_port_wait(efrp_port_t *p, uint32_t ms)
{
    struct timespec end = deadline(ms);
    assert(pthread_mutex_lock(&p->lock) == 0);
    while (!p->signal && ms) {
        int rc = pthread_cond_timedwait(&p->signalled, &p->lock, &end);
        if (rc == ETIMEDOUT) break;
        assert(rc == 0);
    }
    p->signal = false; assert(pthread_mutex_unlock(&p->lock) == 0);
}
uint64_t efrp_port_now_ms(void)
{
    struct timespec t; assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
void efrp_port_destroy(efrp_port_t *p)
{
    if (!p) return;
    if (p->launched) assert(pthread_join(p->thread, NULL) == 0);
    assert(pthread_cond_destroy(&p->changed) == 0); assert(pthread_cond_destroy(&p->signalled) == 0);
    assert(pthread_mutex_destroy(&p->api) == 0); assert(pthread_mutex_destroy(&p->status) == 0);
    assert(pthread_mutex_destroy(&p->lock) == 0); free(p);
}
