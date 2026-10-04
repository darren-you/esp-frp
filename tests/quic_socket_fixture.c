// SPDX-License-Identifier: Apache-2.0
/* Link-time host test syscall interposition only. Production has no hook.
 * Normal mode uses the real connected UDP sendto syscall without recursion. */
#include "quic_socket_fixture.h"
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
static quic_fixture_send_mode_t mode;
static unsigned attempts;
void quic_fixture_send_mode(quic_fixture_send_mode_t next) { mode = next; attempts = 0; }
unsigned quic_fixture_send_attempts(void) { return attempts; }
ssize_t send(int socket, const void *bytes, size_t length, int flags)
{
    ++attempts;
    if (mode == QUIC_FIXTURE_SEND_BLOCK) { errno = EAGAIN; return -1; }
    if (mode == QUIC_FIXTURE_SEND_FAIL) { errno = EIO; return -1; }
    return sendto(socket, bytes, length, flags, NULL, 0);
}
