// SPDX-License-Identifier: Apache-2.0
#include "proxy_internal.h"
#include "esp_frp_wire.h"
#include "crypto_backend.h"
#include "json_internal.h"
#include "memory_internal.h"
#include <string.h>

struct efrp_proxy_owned {
    efrp_proxy_options_t options;
    size_t allocation_bytes;
};

static const efrp_proxy_options_t empty_options;
static const char *const type_names[] = {"tcp", "udp", "stcp", "http", "https", "xtcp"};
static bool text_length(const char *text, size_t maximum, size_t *length)
{
    *length = 0;
    if (!text) return true;
    while (*length <= maximum && text[*length]) ++*length;
    return *length <= maximum && efrp_json_utf8((const uint8_t *)text, *length);
}
static bool ascii_alnum(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
static bool dns_label(const char *text, size_t length)
{
    if (!length || length > 63 || !ascii_alnum((unsigned char)text[0]) ||
        !ascii_alnum((unsigned char)text[length - 1])) return false;
    for (size_t i = 0; i < length; ++i)
        if (!ascii_alnum((unsigned char)text[i]) && text[i] != '-') return false;
    return true;
}
static bool domain_name(const char *text)
{
    size_t length;
    if (!text_length(text, EFRP_PROXY_DOMAIN_MAX_BYTES, &length) || !length) return false;
    size_t first = length > 2 && text[0] == '*' && text[1] == '.' ? 2 : 0;
    for (size_t i = first; i <= length; ++i) {
        if (i == length || text[i] == '.') {
            if (!dns_label(text + first, i - first)) return false;
            first = i + 1;
        }
    }
    return true;
}
static unsigned char ascii_lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}
static bool same_domain(const char *a, const char *b)
{
    for (; *a && *b; ++a, ++b)
        if (ascii_lower((unsigned char)*a) != ascii_lower((unsigned char)*b)) return false;
    return *a == *b;
}
static efrp_result_t validate_options(efrp_proxy_type_t type, const efrp_proxy_options_t *options)
{
    if ((unsigned)type > EFRP_PROXY_XTCP) return EFRP_INVALID_ARGUMENT;
    const efrp_proxy_options_t *o = options ? options : &empty_options;
    size_t secret_length, subdomain_length;
    if (!text_length(o->secret_key, EFRP_PROXY_SECRET_MAX_BYTES, &secret_length) ||
        !text_length(o->subdomain, EFRP_PROXY_SUBDOMAIN_MAX_BYTES, &subdomain_length) ||
        o->custom_domain_count > EFRP_PROXY_DOMAIN_MAX_COUNT ||
        (o->custom_domain_count == 0) != (o->custom_domains == NULL)) return EFRP_INVALID_ARGUMENT;
    if (type == EFRP_PROXY_TCP || type == EFRP_PROXY_UDP)
        return secret_length || subdomain_length || o->custom_domain_count ? EFRP_INVALID_ARGUMENT : EFRP_OK;
    if ((type == EFRP_PROXY_STCP || type == EFRP_PROXY_XTCP))
        return !secret_length || subdomain_length || o->custom_domain_count ? EFRP_INVALID_ARGUMENT : EFRP_OK;
    if (secret_length || (!subdomain_length && !o->custom_domain_count) ||
        (subdomain_length && !dns_label(o->subdomain, subdomain_length))) return EFRP_INVALID_ARGUMENT;
    for (size_t i = 0; i < o->custom_domain_count; ++i) {
        if (!domain_name(o->custom_domains[i])) return EFRP_INVALID_ARGUMENT;
        for (size_t j = 0; j < i; ++j)
            if (same_domain(o->custom_domains[i], o->custom_domains[j])) return EFRP_INVALID_ARGUMENT;
    }
    return EFRP_OK;
}
static size_t escaped_length(const char *text)
{
    size_t length = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\' || *p == '\b' || *p == '\f' ||
            *p == '\n' || *p == '\r' || *p == '\t') length += 2;
        else length += *p < 32 ? 6u : 1u;
    }
    return length;
}
static efrp_result_t registration_length(efrp_proxy_type_t type, const efrp_proxy_options_t *options,
    const char *name, uint16_t port, size_t *length)
{
    *length = 0;
    efrp_result_t result = validate_options(type, options);
    size_t name_length;
    if (result != EFRP_OK) return result;
    if (!text_length(name, 128, &name_length) || !name_length ||
        (type != EFRP_PROXY_TCP && type != EFRP_PROXY_UDP && port)) return EFRP_INVALID_ARGUMENT;
    const efrp_proxy_options_t *o = options ? options : &empty_options;
    size_t n = sizeof "{\"proxy_name\":\"\",\"proxy_type\":\"tcp\",\"use_encryption\":false,\"use_compression\":false}" - 1;
    n += escaped_length(name) + strlen(type_names[type]) - 3;
    if (type == EFRP_PROXY_TCP || type == EFRP_PROXY_UDP) {
        size_t digits = 1;
        for (unsigned value = port; value >= 10; value /= 10) ++digits;
        n += sizeof ",\"remote_port\":" - 1 + digits;
    } else if ((type == EFRP_PROXY_STCP || type == EFRP_PROXY_XTCP)) {
        n += sizeof ",\"sk\":\"\"" - 1 + escaped_length(o->secret_key);
    } else {
        if (o->custom_domain_count) {
            n += sizeof ",\"custom_domains\":[]" - 1;
            for (size_t i = 0; i < o->custom_domain_count; ++i)
                n += strlen(o->custom_domains[i]) + 2 + (i != 0 ? 1u : 0u);
        }
        if (o->subdomain && o->subdomain[0])
            n += sizeof ",\"subdomain\":\"\"" - 1 + strlen(o->subdomain);
    }
    /* cJSON PrintPreallocated requires five extra bytes for its estimates. */
    if (n + 10 + 5 > EFRP_PROXY_REGISTRATION_MAX_BYTES) return EFRP_CAPACITY_EXCEEDED;
    *length = n + 10;
    return EFRP_OK;
}
efrp_result_t efrp_proxy_validate(efrp_proxy_type_t type, const efrp_proxy_options_t *options,
    const char *proxy_name, uint16_t remote_port)
{
    size_t length;
    return registration_length(type, options, proxy_name, remote_port, &length);
}
efrp_result_t efrp_proxy_encode(efrp_proxy_type_t type, const efrp_proxy_options_t *options,
    const char *proxy_name, uint16_t remote_port, uint8_t *output, size_t capacity, size_t *length)
{
    if (length) *length = 0;
    if (capacity > EFRP_PROXY_REGISTRATION_MAX_BYTES) capacity = EFRP_PROXY_REGISTRATION_MAX_BYTES;
    if (output) efrp_crypto_zero(output, capacity);
    if (!output || !length) return EFRP_INVALID_ARGUMENT;
    size_t required;
    efrp_result_t result = registration_length(type, options, proxy_name, remote_port, &required);
    if (result != EFRP_OK) return result;
    if (required + 5 > capacity) return EFRP_CAPACITY_EXCEEDED;
    const efrp_proxy_options_t *o = options ? options : &empty_options;
    cJSON *root = cJSON_CreateObject();
    bool built = root && cJSON_AddStringToObject(root, "proxy_name", proxy_name) &&
        cJSON_AddStringToObject(root, "proxy_type", type_names[type]) &&
        cJSON_AddBoolToObject(root, "use_encryption", false) &&
        cJSON_AddBoolToObject(root, "use_compression", false);
    if (type == EFRP_PROXY_TCP || type == EFRP_PROXY_UDP)
        built = built && cJSON_AddNumberToObject(root, "remote_port", remote_port);
    else if ((type == EFRP_PROXY_STCP || type == EFRP_PROXY_XTCP)) {
        /* Borrow the already-owned secret instead of creating a second secret
         * allocation which cJSON could free internally after an add failure. */
        cJSON *secret = built ? cJSON_CreateStringReference(o->secret_key) : NULL;
        if (!secret) built = false;
        else if (!cJSON_AddItemToObject(root, "sk", secret)) { cJSON_Delete(secret); built = false; }
    }
    else {
        if (o->custom_domain_count) {
            cJSON *domains = built ? cJSON_AddArrayToObject(root, "custom_domains") : NULL;
            built = built && domains;
            for (size_t i = 0; built && i < o->custom_domain_count; ++i) {
                cJSON *domain = cJSON_CreateString(o->custom_domains[i]);
                if (!domain) built = false;
                else if (!cJSON_AddItemToArray(domains, domain)) { cJSON_Delete(domain); built = false; }
            }
        }
        if (o->subdomain && o->subdomain[0])
            built = built && cJSON_AddStringToObject(root, "subdomain", o->subdomain);
    }
    if (!built) result = EFRP_NO_MEMORY;
    else if (!cJSON_PrintPreallocated(root, (char *)output + 10, (int)capacity - 10, 0))
        result = EFRP_CAPACITY_EXCEEDED;
    cJSON_Delete(root);
    if (result == EFRP_OK && strlen((char *)output + 10) + 10 != required) result = EFRP_PROTOCOL_ERROR;
    if (result == EFRP_OK) result = efrp_wire_header(EFRP_MESSAGE, required - 8, output);
    if (result != EFRP_OK) { efrp_crypto_zero(output, capacity); return result; }
    output[8] = 0; output[9] = 3; *length = required;
    return EFRP_OK;
}
efrp_result_t efrp_proxy_owned_clone(efrp_proxy_type_t type,
    const efrp_proxy_options_t *options, efrp_proxy_owned_t **out)
{
    if (!out) return EFRP_INVALID_ARGUMENT;
    if (*out) return EFRP_INVALID_STATE;
    efrp_result_t result = validate_options(type, options);
    if (result != EFRP_OK || type == EFRP_PROXY_TCP || type == EFRP_PROXY_UDP) return result;
    const efrp_proxy_options_t *o = options;
    size_t secret_length = o->secret_key ? strlen(o->secret_key) : 0;
    size_t subdomain_length = o->subdomain ? strlen(o->subdomain) : 0;
    size_t bytes = sizeof(efrp_proxy_owned_t) + o->custom_domain_count * sizeof(char *);
    if (secret_length) bytes += secret_length + 1;
    if (subdomain_length) bytes += subdomain_length + 1;
    for (size_t i = 0; i < o->custom_domain_count; ++i) bytes += strlen(o->custom_domains[i]) + 1;
    efrp_proxy_owned_t *owner = efrp_heap_calloc(bytes);
    if (!owner) return EFRP_NO_MEMORY;
    owner->allocation_bytes = bytes;
    char **domains = (char **)(owner + 1);
    char *next = (char *)(domains + o->custom_domain_count);
    if (secret_length) {
        owner->options.secret_key = next;
        memcpy(next, o->secret_key, secret_length + 1); next += secret_length + 1;
    }
    if (subdomain_length) {
        owner->options.subdomain = next;
        memcpy(next, o->subdomain, subdomain_length + 1); next += subdomain_length + 1;
    }
    owner->options.custom_domain_count = o->custom_domain_count;
    if (o->custom_domain_count) owner->options.custom_domains = (const char *const *)domains;
    for (size_t i = 0; i < o->custom_domain_count; ++i) {
        size_t n = strlen(o->custom_domains[i]) + 1;
        domains[i] = next; memcpy(next, o->custom_domains[i], n); next += n;
    }
    *out = owner;
    return EFRP_OK;
}
const efrp_proxy_options_t *efrp_proxy_owned_options(const efrp_proxy_owned_t *owner)
{
    return owner ? &owner->options : NULL;
}
void efrp_proxy_owned_destroy(efrp_proxy_owned_t **owner)
{
    if (!owner || !*owner) return;
    efrp_proxy_owned_t *value = *owner;
    size_t bytes = value->allocation_bytes;
    efrp_crypto_zero(value, bytes); free(value); *owner = NULL;
}
