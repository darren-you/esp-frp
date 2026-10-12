// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "sample_udp_echo.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static bool fail_close, block_send;
static unsigned blocked_sends;
static int retained_fd=-1;
int fixture_sample_udp_close(int fd)
{
    if (fail_close) { fail_close=false; retained_fd=fd; errno=EAGAIN; return -1; }
    if (retained_fd >= 0) assert(fd == retained_fd);
    return close(fd);
}
ssize_t fixture_sample_udp_sendto(int fd, const void *bytes, size_t length, int flags,
    const struct sockaddr *address, socklen_t address_length)
{
    if (block_send) { ++blocked_sends; errno=EAGAIN; return -1; }
    return sendto(fd,bytes,length,flags,address,address_length);
}
static uint16_t reserve_port(void)
{
    int fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); assert(fd >= 0);
    struct sockaddr_in address={.sin_family=AF_INET, .sin_addr.s_addr=htonl(UINT32_C(0x7f000001))};
    assert(!bind(fd,(struct sockaddr *)&address,sizeof address));
    socklen_t length=sizeof address; assert(!getsockname(fd,(struct sockaddr *)&address,&length));
    assert(!close(fd)); return ntohs(address.sin_port);
}
static void wait_ms(void) { const struct timespec delay={0,1000000}; (void)nanosleep(&delay,NULL); }
static void exchange(int fd, const uint8_t *payload, size_t length)
{
    assert(send(fd,payload,length,0) == (ssize_t)length);
    uint8_t response[1501];
    for (unsigned i=0; i<1000; ++i) {
        sample_udp_echo_step(); ssize_t n=recv(fd,response,sizeof response,0);
        if (n >= 0) { assert((size_t)n == length && !memcmp(response,payload,length)); return; }
        assert(errno == EAGAIN || errno == EWOULDBLOCK); wait_ms();
    }
    assert(false);
}
int main(void)
{
    uint16_t port=reserve_port();
    assert(!sample_udp_echo_start(port,0) && !sample_udp_echo_start(port,1501));
    assert(sample_udp_echo_start(port,1500));
    int clients[2];
    struct sockaddr_in address={.sin_family=AF_INET, .sin_addr.s_addr=htonl(UINT32_C(0x7f000001)), .sin_port=htons(port)};
    for (unsigned i=0;i<2;++i) {
        clients[i]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); assert(clients[i]>=0);
        assert(!fcntl(clients[i],F_SETFL,O_NONBLOCK));
        assert(!connect(clients[i],(struct sockaddr *)&address,sizeof address));
    }
    uint8_t bytes[3000]; for (unsigned i=0;i<sizeof bytes;++i) bytes[i]=(uint8_t)(i*31u+17u);
    exchange(clients[0],bytes,0); exchange(clients[0],bytes,1); exchange(clients[1],bytes,1500);
    assert(send(clients[0],bytes,1501,0)==1501 && send(clients[0],bytes,sizeof bytes,0)==(ssize_t)sizeof bytes);
    for (unsigned i=0;i<30;++i) { sample_udp_echo_step(); wait_ms(); }
    uint8_t response[1501]; assert(recv(clients[0],response,sizeof response,0)<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
    exchange(clients[1],bytes,37);
    block_send=true;
    assert(send(clients[0],bytes,37,0)==37);
    for (unsigned i=0;i<1000 && !blocked_sends;++i) { sample_udp_echo_step(); wait_ms(); }
    assert(blocked_sends); /* A real received packet is retained on send EAGAIN. */
    sample_udp_echo_clear_pending(); block_send=false;
    for (unsigned i=0;i<30;++i) { sample_udp_echo_step(); wait_ms(); }
    assert(recv(clients[0],response,sizeof response,0)<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
    exchange(clients[1],bytes,41);
    fail_close=true; sample_udp_echo_stop();
    assert(retained_fd>=0 && fcntl(retained_fd,F_GETFD)>=0);
    assert(!sample_udp_echo_start(port,1500)); /* Retained owner blocks restart. */
    sample_udp_echo_step(); assert(fcntl(retained_fd,F_GETFD)<0 && errno==EBADF);
    retained_fd=-1;
    assert(sample_udp_echo_start(port,1500)); exchange(clients[0],bytes,1500);
    assert(sample_udp_echo_stop() && sample_udp_echo_stop());
    int occupied=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); assert(occupied>=0);
    assert(!bind(occupied,(struct sockaddr *)&address,sizeof address));
    fail_close=true;
    assert(!sample_udp_echo_start(port,1500)); /* bind fails; first cleanup close also fails. */
    assert(retained_fd>=0 && fcntl(retained_fd,F_GETFD)>=0);
    assert(!sample_udp_echo_start(port,1500));
    sample_udp_echo_step(); assert(fcntl(retained_fd,F_GETFD)<0 && errno==EBADF);
    retained_fd=-1; assert(!close(occupied));
    assert(sample_udp_echo_start(port,1500) && sample_udp_echo_stop());
    for (unsigned i=0;i<2;++i) assert(!close(clients[i]));
    return 0;
}
