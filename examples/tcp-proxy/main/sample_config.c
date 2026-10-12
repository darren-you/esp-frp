// SPDX-License-Identifier: Apache-2.0
#include "sample_config.h"
#include <string.h>

static bool loopback(const uint8_t address[4])
{
    const uint8_t expected[4] = {127, 0, 0, 1};
    return !memcmp(address, expected, sizeof expected);
}
static bool endpoint(const uint8_t address[4], uint16_t port)
{
    return address[0] && address[0] < 224 && port;
}
bool sample_config_valid(const sample_configuration_t *configuration)
{
    if (!configuration) return false;
    switch (configuration->role) {
    case SAMPLE_ROLE_PROVIDER: {
        const efrp_config_t *config = &configuration->client.provider;
        if (!config->ca_pem || !config->ca_length || !config->token || !config->token_length ||
            !endpoint(config->local_ipv4, config->local_port)) return false;
        switch (config->proxy_type) {
        case EFRP_PROXY_TCP:
        case EFRP_PROXY_STCP:
        case EFRP_PROXY_XTCP:
            return configuration->backend == SAMPLE_BACKEND_TCP_ECHO && loopback(config->local_ipv4);
        case EFRP_PROXY_UDP:
            return configuration->backend == SAMPLE_BACKEND_UDP_ECHO && loopback(config->local_ipv4) &&
                config->udp_packet_size && config->udp_packet_size <= SAMPLE_UDP_MAX_BYTES;
        case EFRP_PROXY_HTTP:
        case EFRP_PROXY_HTTPS:
            /* The fixture supplies real HTTP/auth/TLS. No business TLS is
             * terminated here, and the explicit destination never changes. */
            return configuration->backend == SAMPLE_BACKEND_EXTERNAL && config->local_ipv4[0] != 127;
        default: return false;
        }
    }
    case SAMPLE_ROLE_STCP_VISITOR: {
        const efrp_stcp_visitor_config_t *config = &configuration->client.stcp_visitor;
        return configuration->backend == SAMPLE_BACKEND_NONE &&
            config->ca_pem && config->ca_length && config->token && config->token_length &&
            endpoint(config->bind_ipv4, config->bind_port);
    }
    case SAMPLE_ROLE_XTCP_VISITOR: {
        const efrp_xtcp_visitor_config_t *config = &configuration->client.xtcp_visitor;
        return configuration->backend == SAMPLE_BACKEND_NONE &&
            config->ca_pem && config->ca_length && config->token && config->token_length &&
            endpoint(config->bind_ipv4, config->bind_port);
    }
    default: return false;
    }
}
uint16_t sample_config_backend_port(const sample_configuration_t *configuration)
{
    return configuration && configuration->role == SAMPLE_ROLE_PROVIDER ? configuration->client.provider.local_port : 0;
}
efrp_transport_kind_t sample_config_transport(const sample_configuration_t *configuration)
{
    if (configuration->role == SAMPLE_ROLE_STCP_VISITOR) return configuration->client.stcp_visitor.transport;
    if (configuration->role == SAMPLE_ROLE_XTCP_VISITOR) return configuration->client.xtcp_visitor.transport;
    return configuration->client.provider.transport;
}
efrp_result_t sample_config_create(const sample_configuration_t *configuration,
    efrp_time_trusted_t trusted, const efrp_aead_flash_store_t *store,
    const char *run_id, efrp_client_t **client)
{
    if (!sample_config_valid(configuration)) return EFRP_INVALID_ARGUMENT;
    switch (configuration->role) {
    case SAMPLE_ROLE_PROVIDER: {
        efrp_config_t config = configuration->client.provider;
        config.time_is_trusted = trusted; config.flash_store = store;
        if (run_id && run_id[0]) config.run_id = run_id;
        return efrp_create(&config, client);
    }
    case SAMPLE_ROLE_STCP_VISITOR: {
        efrp_stcp_visitor_config_t config = configuration->client.stcp_visitor;
        config.time_is_trusted = trusted; config.flash_store = store;
        if (run_id && run_id[0]) config.run_id = run_id;
        return efrp_stcp_visitor_create(&config, client);
    }
    case SAMPLE_ROLE_XTCP_VISITOR: {
        efrp_xtcp_visitor_config_t config = configuration->client.xtcp_visitor;
        config.time_is_trusted = trusted; config.flash_store = store;
        if (run_id && run_id[0]) config.run_id = run_id;
        return efrp_xtcp_visitor_create(&config, client);
    }
    default: return EFRP_INVALID_ARGUMENT;
    }
}
