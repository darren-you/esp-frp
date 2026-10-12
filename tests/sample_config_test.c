// SPDX-License-Identifier: Apache-2.0
#include "sample_config.h"
#include <assert.h>
#include <string.h>

static unsigned called;
static efrp_config_t provider;
static efrp_stcp_visitor_config_t stcp;
static efrp_xtcp_visitor_config_t xtcp;
static bool trusted(void *context) { return context != NULL; }
efrp_result_t efrp_create(const efrp_config_t *config, efrp_client_t **client)
{ (void)client; called = 1; provider = *config; return EFRP_WOULD_BLOCK; }
efrp_result_t efrp_stcp_visitor_create(const efrp_stcp_visitor_config_t *config, efrp_client_t **client)
{ (void)client; called = 2; stcp = *config; return EFRP_WOULD_BLOCK; }
efrp_result_t efrp_xtcp_visitor_create(const efrp_xtcp_visitor_config_t *config, efrp_client_t **client)
{ (void)client; called = 3; xtcp = *config; return EFRP_WOULD_BLOCK; }
int main(void)
{
    static const uint8_t ca[] = "explicit-ca", token[] = "explicit-token";
    static const efrp_aead_flash_store_t store = {0};
    efrp_client_t *client = NULL;
    sample_configuration_t config = {.role=SAMPLE_ROLE_PROVIDER, .backend=SAMPLE_BACKEND_TCP_ECHO,
        .client.provider={.ca_pem=ca, .ca_length=sizeof ca-1, .token=token, .token_length=sizeof token-1,
            .proxy_type=EFRP_PROXY_TCP, .local_ipv4={127,0,0,1}, .local_port=8765, .run_id="input-run", .context=&client}};
    config.role=SAMPLE_ROLE_INVALID; called=0;
    assert(sample_config_create(&config, trusted, &store, NULL, &client) == EFRP_INVALID_ARGUMENT && !called);
    config.role=SAMPLE_ROLE_PROVIDER; config.backend=SAMPLE_BACKEND_INVALID;
    assert(sample_config_create(&config, trusted, &store, NULL, &client) == EFRP_INVALID_ARGUMENT && !called);
    config.backend=SAMPLE_BACKEND_TCP_ECHO;
    assert(sample_config_valid(&config) && sample_config_backend_port(&config) == 8765);
    assert(sample_config_create(&config, trusted, &store, "", &client) == EFRP_WOULD_BLOCK && called == 1);
    assert(provider.time_is_trusted == trusted && provider.flash_store == &store && provider.context == &client);
    assert(!strcmp(provider.run_id, "input-run"));
    assert(sample_config_create(&config, trusted, &store, "authenticated-run", &client) == EFRP_WOULD_BLOCK);
    assert(!strcmp(provider.run_id, "authenticated-run") && !strcmp(config.client.provider.run_id, "input-run"));
    config.client.provider.transport=EFRP_TRANSPORT_QUIC;
    config.client.provider.quic_profile=EFRP_QUIC_PROFILE_P256_AES128_X25519;
    assert(sample_config_transport(&config) == EFRP_TRANSPORT_QUIC);
    assert(sample_config_create(&config, trusted, &store, NULL, &client) == EFRP_WOULD_BLOCK);
    assert(provider.transport == EFRP_TRANSPORT_QUIC && provider.quic_profile == EFRP_QUIC_PROFILE_P256_AES128_X25519);
    const efrp_proxy_type_t tcp_types[] = {EFRP_PROXY_STCP, EFRP_PROXY_XTCP};
    for (unsigned i=0; i<sizeof tcp_types/sizeof tcp_types[0]; ++i) {
        config.client.provider.proxy_type=tcp_types[i]; assert(sample_config_valid(&config));
    }
    config.client.provider.proxy_type=EFRP_PROXY_UDP;
    assert(!sample_config_valid(&config));
    config.backend=SAMPLE_BACKEND_UDP_ECHO; config.client.provider.udp_packet_size=1500;
    assert(sample_config_valid(&config));
    config.client.provider.udp_packet_size=1501; assert(!sample_config_valid(&config));
    config.client.provider.udp_packet_size=0; assert(!sample_config_valid(&config));
    const efrp_proxy_type_t http_types[] = {EFRP_PROXY_HTTP, EFRP_PROXY_HTTPS};
    for (unsigned i=0; i<sizeof http_types/sizeof http_types[0]; ++i) {
        config.client.provider.proxy_type=http_types[i]; config.backend=SAMPLE_BACKEND_EXTERNAL;
        assert(!sample_config_valid(&config));
        config.client.provider.local_ipv4[0]=192;
        assert(sample_config_valid(&config));
        assert(sample_config_create(&config, trusted, &store, NULL, &client) == EFRP_WOULD_BLOCK && provider.proxy_type == http_types[i]);
        assert(provider.local_ipv4[0] == 192 && provider.local_port == 8765);
        config.client.provider.local_ipv4[0]=127;
    }
    config.client.provider.proxy_type=(efrp_proxy_type_t)99; called=0;
    assert(sample_config_create(&config, trusted, &store, NULL, &client) == EFRP_INVALID_ARGUMENT && !called);
    memset(&config, 0, sizeof config); config.role=SAMPLE_ROLE_STCP_VISITOR; config.backend=SAMPLE_BACKEND_NONE;
    config.client.stcp_visitor=(efrp_stcp_visitor_config_t){.ca_pem=ca, .ca_length=sizeof ca-1,
        .token=token, .token_length=sizeof token-1, .bind_ipv4={192,168,1,2}, .bind_port=8766,
        .server_proxy_name="user.private", .secret_key="explicit-secret", .run_id="visitor-input",
        .transport=EFRP_TRANSPORT_QUIC, .quic_profile=EFRP_QUIC_PROFILE_P256_AES128_X25519};
    assert(sample_config_valid(&config) && !sample_config_backend_port(&config));
    assert(sample_config_transport(&config) == EFRP_TRANSPORT_QUIC);
    assert(sample_config_create(&config, trusted, &store, NULL, &client) == EFRP_WOULD_BLOCK && called == 2);
    assert(stcp.flash_store == &store && stcp.time_is_trusted == trusted && stcp.bind_port == 8766);
    assert(!strcmp(stcp.secret_key, "explicit-secret") && !strcmp(stcp.run_id, "visitor-input"));
    config.backend=SAMPLE_BACKEND_TCP_ECHO; called=0;
    assert(sample_config_create(&config, trusted, &store, NULL, &client) == EFRP_INVALID_ARGUMENT && !called);
    memset(&config, 0, sizeof config); config.role=SAMPLE_ROLE_XTCP_VISITOR; config.backend=SAMPLE_BACKEND_NONE;
    config.client.xtcp_visitor=(efrp_xtcp_visitor_config_t){.ca_pem=ca, .ca_length=sizeof ca-1,
        .token=token, .token_length=sizeof token-1, .bind_ipv4={192,168,1,2}, .bind_port=8766,
        .server_proxy_name="user.private", .secret_key="explicit-secret",
        .options={.peer_profile=EFRP_QUIC_PROFILE_P256_AES128_X25519,
            .stun_servers={{{192,168,1,3},3478}}, .stun_server_count=1}};
    assert(sample_config_valid(&config));
    assert(sample_config_create(&config, trusted, &store, "authenticated-run", &client) == EFRP_WOULD_BLOCK && called == 3);
    assert(xtcp.flash_store == &store && xtcp.time_is_trusted == trusted && xtcp.options.stun_server_count == 1);
    assert(xtcp.options.stun_servers[0].ipv4[3] == 3 && !strcmp(xtcp.run_id, "authenticated-run"));
    config.client.xtcp_visitor.bind_ipv4[0]=0; assert(!sample_config_valid(&config));
    config.role=(sample_role_t)99; called=0;
    assert(sample_config_create(&config, trusted, &store, NULL, &client) == EFRP_INVALID_ARGUMENT && !called);
    assert(!sample_config_valid(NULL));
    return 0;
}
