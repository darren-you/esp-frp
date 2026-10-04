// SPDX-License-Identifier: Apache-2.0
#include "proxy_internal.h"
#include "json_internal.h"
#include "esp_frp_wire.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t output[EFRP_PROXY_REGISTRATION_MAX_BYTES];
static void cleared(const void *memory, size_t length)
{
    const uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) assert(!bytes[i]);
}
static cJSON *registration(efrp_proxy_type_t type, const efrp_proxy_options_t *options,
    const char *name, uint16_t port)
{
    size_t length;
    memset(output, 0xa5, sizeof output);
    assert(efrp_proxy_validate(type, options, name, port) == EFRP_OK);
    assert(efrp_proxy_encode(type, options, name, port, output, sizeof output, &length) == EFRP_OK);
    assert(length > 10 && length + 5 <= sizeof output);
    assert(output[0] == 0 && output[1] == EFRP_MESSAGE && output[2] == 0 && output[3] == 0);
    size_t payload = ((size_t)output[4] << 24) | ((size_t)output[5] << 16) |
        ((size_t)output[6] << 8) | output[7];
    assert(payload + 8 == length && output[8] == 0 && output[9] == 3);
    cleared(output + length, sizeof output - length);
    cJSON *root = efrp_json_parse(output + 10, length - 10, EFRP_JSON_CONTROL_MAX_PUNCTUATION);
    assert(root && efrp_json_equals(root, "proxy_name", name));
    const cJSON *encryption = efrp_json_field(root, "use_encryption");
    const cJSON *compression = efrp_json_field(root, "use_compression");
    assert(cJSON_IsFalse(encryption) && cJSON_IsFalse(compression));
    /* The caller's exact buffer requirement includes cJSON's five-byte reserve. */
    uint8_t exact[EFRP_PROXY_REGISTRATION_MAX_BYTES]; size_t exact_length;
    assert(efrp_proxy_encode(type, options, name, port, exact, length + 5, &exact_length) == EFRP_OK);
    assert(exact_length == length && !memcmp(exact, output, length));
    memset(exact, 0xa5, sizeof exact); exact_length = 123;
    assert(efrp_proxy_encode(type, options, name, port, exact, length + 4, &exact_length) == EFRP_CAPACITY_EXCEEDED);
    assert(!exact_length); cleared(exact, length + 4);
    assert(exact[length + 4] == 0xa5);
    return root;
}
static void type_fields(void)
{
    const char *const tcp_fields[] = {"proxy_name", "proxy_type", "use_encryption", "use_compression", "remote_port"};
    for (unsigned type = EFRP_PROXY_TCP; type <= EFRP_PROXY_UDP; ++type) {
        for (unsigned i = 0; i < 2; ++i) {
            uint16_t port = i ? UINT16_MAX : 0;
            cJSON *root = registration((efrp_proxy_type_t)type, NULL, "public-proxy", port);
            assert(efrp_json_shape(root, tcp_fields, 5));
            assert(efrp_json_equals(root, "proxy_type", type == EFRP_PROXY_TCP ? "tcp" : "udp"));
            const cJSON *remote = efrp_json_field(root, "remote_port");
            assert(cJSON_IsNumber(remote) && remote->valuedouble == port);
            cJSON_Delete(root);
        }
    }
    const char *const stcp_fields[] = {"proxy_name", "proxy_type", "use_encryption", "use_compression", "sk"};
    const char *secret = "public-test-secret\"\\\n\x01\xe4\xb8\xad";
    efrp_proxy_options_t stcp = {.secret_key = secret};
    cJSON *root = registration(EFRP_PROXY_STCP, &stcp, "public\"\\\n\xe4\xb8\xad", 0);
    assert(efrp_json_shape(root, stcp_fields, 5));
    assert(efrp_json_equals(root, "proxy_type", "stcp") && efrp_json_equals(root, "sk", secret));
    assert(!strcmp(stcp.secret_key, secret)); cJSON_Delete(root);
    const char *domains[] = {"Example.test", "*.example.test", "xn--fiqs8s.test"};
    efrp_proxy_options_t web = {.custom_domains = domains, .custom_domain_count = 3, .subdomain = "device-1"};
    const char *const web_fields[] = {"proxy_name", "proxy_type", "use_encryption", "use_compression", "custom_domains", "subdomain"};
    for (unsigned type = EFRP_PROXY_HTTP; type <= EFRP_PROXY_HTTPS; ++type) {
        root = registration((efrp_proxy_type_t)type, &web, "web-proxy", 0);
        assert(efrp_json_shape(root, web_fields, 6));
        assert(efrp_json_equals(root, "proxy_type", type == EFRP_PROXY_HTTP ? "http" : "https"));
        assert(efrp_json_equals(root, "subdomain", "device-1"));
        const cJSON *array = efrp_json_field(root, "custom_domains");
        assert(cJSON_IsArray(array) && cJSON_GetArraySize(array) == 3);
        for (int i = 0; i < 3; ++i) {
            const cJSON *domain = cJSON_GetArrayItem(array, i);
            assert(cJSON_IsString(domain) && !strcmp(domain->valuestring, domains[i]));
        }
        cJSON_Delete(root);
    }
    web.custom_domains = NULL; web.custom_domain_count = 0;
    root = registration(EFRP_PROXY_HTTP, &web, "subdomain-only", 0);
    assert(!efrp_json_field(root, "custom_domains")); cJSON_Delete(root);
    web = (efrp_proxy_options_t){.custom_domains = domains, .custom_domain_count = 1};
    root = registration(EFRP_PROXY_HTTPS, &web, "domain-only", 0);
    assert(!efrp_json_field(root, "subdomain")); cJSON_Delete(root);
}
static void rejected(efrp_proxy_type_t type, const efrp_proxy_options_t *options,
    const char *name, uint16_t port, efrp_result_t expected)
{
    assert(efrp_proxy_validate(type, options, name, port) == expected);
    size_t length = 99; memset(output, 0xa5, sizeof output);
    assert(efrp_proxy_encode(type, options, name, port, output, sizeof output, &length) == expected);
    assert(!length); cleared(output, sizeof output);
}
static void invalid_options(void)
{
    const char *domains[] = {"example.test"};
    const efrp_proxy_options_t empty = {0}, secret = {.secret_key = "public-test-secret"};
    efrp_proxy_options_t web = {.custom_domains = domains, .custom_domain_count = 1};
    rejected((efrp_proxy_type_t)-1, NULL, "proxy", 0, EFRP_INVALID_ARGUMENT);
    rejected((efrp_proxy_type_t)6, NULL, "proxy", 0, EFRP_INVALID_ARGUMENT);
    rejected(EFRP_PROXY_TCP, NULL, NULL, 0, EFRP_INVALID_ARGUMENT);
    rejected(EFRP_PROXY_TCP, NULL, "", 0, EFRP_INVALID_ARGUMENT);
    rejected(EFRP_PROXY_TCP, NULL, "\xc0\x80", 0, EFRP_INVALID_ARGUMENT);
    for (unsigned type = EFRP_PROXY_TCP; type <= EFRP_PROXY_UDP; ++type) {
        rejected((efrp_proxy_type_t)type, &secret, "proxy", 0, EFRP_INVALID_ARGUMENT);
        rejected((efrp_proxy_type_t)type, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
        assert(efrp_proxy_validate((efrp_proxy_type_t)type, &empty, "proxy", 0) == EFRP_OK);
    }
    rejected(EFRP_PROXY_STCP, NULL, "proxy", 0, EFRP_INVALID_ARGUMENT);
    rejected(EFRP_PROXY_STCP, &empty, "proxy", 0, EFRP_INVALID_ARGUMENT);
    rejected(EFRP_PROXY_STCP, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
    rejected(EFRP_PROXY_STCP, &secret, "proxy", 1, EFRP_INVALID_ARGUMENT);
    for (unsigned type = EFRP_PROXY_HTTP; type <= EFRP_PROXY_HTTPS; ++type) {
        rejected((efrp_proxy_type_t)type, NULL, "proxy", 0, EFRP_INVALID_ARGUMENT);
        rejected((efrp_proxy_type_t)type, &secret, "proxy", 0, EFRP_INVALID_ARGUMENT);
        rejected((efrp_proxy_type_t)type, &web, "proxy", 1, EFRP_INVALID_ARGUMENT);
    }
    web.secret_key = "public-test-secret";
    rejected(EFRP_PROXY_HTTP, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
    web.secret_key = NULL; web.custom_domain_count = 0;
    rejected(EFRP_PROXY_HTTP, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
    web.custom_domain_count = 1; web.custom_domains = NULL;
    rejected(EFRP_PROXY_HTTP, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
    const char *duplicates[] = {"Example.test", "example.TEST"};
    web = (efrp_proxy_options_t){.custom_domains = duplicates, .custom_domain_count = 2};
    rejected(EFRP_PROXY_HTTP, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
    const char *bad_domains[] = {NULL, "", ".example.test", "example.test.", "*.test.*", "*", "-bad.test",
        "bad-.test", "bad_test", "https://example.test", "example.test:443", "example..test", "\xe4\xb8\xad.test"};
    for (size_t i = 0; i < sizeof bad_domains / sizeof bad_domains[0]; ++i) {
        const char *one[] = {bad_domains[i]};
        web = (efrp_proxy_options_t){.custom_domains = one, .custom_domain_count = 1};
        rejected(EFRP_PROXY_HTTP, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
    }
    const char *bad_subdomains[] = {"", "*.device", "device.test", "-device", "device-", "device_name", "\xe4\xb8\xad"};
    for (size_t i = 0; i < sizeof bad_subdomains / sizeof bad_subdomains[0]; ++i) {
        web = (efrp_proxy_options_t){.subdomain = bad_subdomains[i]};
        rejected(EFRP_PROXY_HTTPS, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
    }
    web = (efrp_proxy_options_t){.custom_domains = domains, .custom_domain_count = EFRP_PROXY_DOMAIN_MAX_COUNT + 1};
    rejected(EFRP_PROXY_HTTP, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
}
static void bounds(void)
{
    char name[130], secret[130], subdomain[65], domain[255];
    memset(name, 'n', sizeof name - 1); name[sizeof name - 1] = 0;
    rejected(EFRP_PROXY_TCP, NULL, name, 0, EFRP_INVALID_ARGUMENT); name[128] = 0;
    cJSON *root = registration(EFRP_PROXY_TCP, NULL, name, UINT16_MAX); cJSON_Delete(root);
    memset(secret, 's', sizeof secret - 1); secret[sizeof secret - 1] = 0;
    efrp_proxy_options_t stcp = {.secret_key = secret};
    rejected(EFRP_PROXY_STCP, &stcp, "proxy", 0, EFRP_INVALID_ARGUMENT); secret[128] = 0;
    root = registration(EFRP_PROXY_STCP, &stcp, name, 0); cJSON_Delete(root);
    memset(subdomain, 'd', sizeof subdomain - 1); subdomain[sizeof subdomain - 1] = 0;
    efrp_proxy_options_t web = {.subdomain = subdomain};
    rejected(EFRP_PROXY_HTTP, &web, "proxy", 0, EFRP_INVALID_ARGUMENT); subdomain[63] = 0;
    root = registration(EFRP_PROXY_HTTP, &web, "proxy", 0); cJSON_Delete(root);
    memset(domain, 'd', 253); domain[63] = domain[127] = domain[191] = '.'; domain[253] = 0;
    const char *domains[] = {domain};
    web = (efrp_proxy_options_t){.custom_domains = domains, .custom_domain_count = 1};
    root = registration(EFRP_PROXY_HTTPS, &web, "proxy", 0); cJSON_Delete(root);
    domain[253] = 'd'; domain[254] = 0;
    rejected(EFRP_PROXY_HTTPS, &web, "proxy", 0, EFRP_INVALID_ARGUMENT);
    char large[4][254]; const char *many[4];
    for (unsigned i = 0; i < 4; ++i) { memcpy(large[i], domain, 253); large[i][0] = (char)('a' + i); large[i][253] = 0; many[i] = large[i]; }
    web = (efrp_proxy_options_t){.custom_domains = many, .custom_domain_count = 4};
    rejected(EFRP_PROXY_HTTP, &web, "proxy", 0, EFRP_CAPACITY_EXCEEDED);
    memset(secret, 1, 128); secret[128] = 0;
    memset(name, '"', 128); name[128] = 0;
    rejected(EFRP_PROXY_STCP, &stcp, name, 0, EFRP_CAPACITY_EXCEEDED);
}
static void xtcp_contract(void)
{
    assert(EFRP_PROXY_TCP==0 && EFRP_PROXY_UDP==1 && EFRP_PROXY_STCP==2 && EFRP_PROXY_HTTP==3 && EFRP_PROXY_HTTPS==4 && EFRP_PROXY_XTCP==5);
    const char *const fields[]={"proxy_name","proxy_type","use_encryption","use_compression","sk"};
    char secret[130]; memset(secret,'s',128); secret[128]=0;
    efrp_proxy_options_t options={.secret_key=secret};
    cJSON *root=registration(EFRP_PROXY_XTCP,&options,"provider.private",0);
    assert(efrp_json_shape(root,fields,5)&&efrp_json_equals(root,"proxy_type","xtcp")&&efrp_json_equals(root,"sk",secret));
    assert(!efrp_json_field(root,"remote_port")&&!efrp_json_field(root,"allow_users"));cJSON_Delete(root);
    rejected(EFRP_PROXY_XTCP,NULL,"provider",0,EFRP_INVALID_ARGUMENT);
    efrp_proxy_options_t empty={0}; rejected(EFRP_PROXY_XTCP,&empty,"provider",0,EFRP_INVALID_ARGUMENT);
    rejected(EFRP_PROXY_XTCP,&options,"provider",1,EFRP_INVALID_ARGUMENT);
    options.subdomain="device";rejected(EFRP_PROXY_XTCP,&options,"provider",0,EFRP_INVALID_ARGUMENT);options.subdomain=NULL;
    const char *domains[]={"example.test"};options.custom_domains=domains;options.custom_domain_count=1;
    rejected(EFRP_PROXY_XTCP,&options,"provider",0,EFRP_INVALID_ARGUMENT);options.custom_domains=NULL;options.custom_domain_count=0;
    secret[128]='s';secret[129]=0;rejected(EFRP_PROXY_XTCP,&options,"provider",0,EFRP_INVALID_ARGUMENT);secret[128]=0;
    efrp_proxy_owned_t *owner=NULL;assert(efrp_proxy_owned_clone(EFRP_PROXY_XTCP,&options,&owner)==EFRP_OK&&owner);
    secret[0]='!';root=registration(EFRP_PROXY_XTCP,efrp_proxy_owned_options(owner),"owned-provider",0);
    assert(efrp_json_string(root,"sk")[0]=='s');cJSON_Delete(root);efrp_proxy_owned_destroy(&owner);assert(!owner);
    memset(secret,1,128);secret[128]=0;char name[129];memset(name,'"',128);name[128]=0;
    rejected(EFRP_PROXY_XTCP,&options,name,0,EFRP_CAPACITY_EXCEEDED);
}
static void owned_inputs(void)
{
    efrp_proxy_owned_t *owner = NULL;
    assert(efrp_proxy_owned_clone(EFRP_PROXY_TCP, NULL, &owner) == EFRP_OK && !owner);
    assert(!efrp_proxy_owned_options(owner)); efrp_proxy_owned_destroy(&owner);
    assert(efrp_proxy_owned_clone(EFRP_PROXY_UDP, NULL, &owner) == EFRP_OK && !owner);
    assert(efrp_proxy_owned_clone(EFRP_PROXY_STCP, NULL, &owner) == EFRP_INVALID_ARGUMENT && !owner);
    char secret[] = "public-test-secret";
    efrp_proxy_options_t options = {.secret_key = secret};
    assert(efrp_proxy_owned_clone(EFRP_PROXY_STCP, &options, &owner) == EFRP_OK && owner);
    efrp_proxy_owned_t *saved = owner;
    assert(efrp_proxy_owned_clone(EFRP_PROXY_TCP, NULL, &owner) == EFRP_INVALID_STATE && owner == saved);
    secret[0] = '!'; options.secret_key = NULL;
    const efrp_proxy_options_t *copy = efrp_proxy_owned_options(owner);
    assert(copy && copy->secret_key != secret && !strcmp(copy->secret_key, "public-test-secret"));
    cJSON *root = registration(EFRP_PROXY_STCP, copy, "owned", 0); cJSON_Delete(root);
    efrp_proxy_owned_destroy(&owner); assert(!owner); efrp_proxy_owned_destroy(&owner);
    char first[] = "example.test", second[] = "*.example.test", subdomain[] = "device-1";
    const char *domains[] = {first, second};
    options = (efrp_proxy_options_t){.custom_domains = domains, .custom_domain_count = 2, .subdomain = subdomain};
    assert(efrp_proxy_owned_clone(EFRP_PROXY_HTTP, &options, &owner) == EFRP_OK && owner);
    first[0] = '!'; second[0] = '!'; subdomain[0] = '!'; domains[0] = NULL;
    copy = efrp_proxy_owned_options(owner);
    assert(copy && copy->custom_domains != domains && copy->custom_domain_count == 2);
    assert(!strcmp(copy->custom_domains[0], "example.test") && !strcmp(copy->custom_domains[1], "*.example.test"));
    assert(!strcmp(copy->subdomain, "device-1"));
    root = registration(EFRP_PROXY_HTTP, copy, "owned", 0); cJSON_Delete(root);
    efrp_proxy_owned_destroy(&owner); assert(!owner);
    efrp_proxy_owned_destroy(NULL);
}
static size_t allocation_limit, allocations, outstanding;
static void *limited_malloc(size_t length)
{
    void *memory = allocations++ < allocation_limit ? malloc(length) : NULL;
    if (memory) ++outstanding;
    return memory;
}
static void limited_free(void *memory)
{
    if (memory) { assert(outstanding); --outstanding; free(memory); }
}
static void allocation_failures(void)
{
    char secret[] = "public-test-secret";
    const char *domains[] = {"example.test", "*.example.test"};
    efrp_proxy_options_t options[] = {{.secret_key = secret}, {.custom_domains = domains, .custom_domain_count = 2, .subdomain = "device"}};
    cJSON_Hooks hooks = {.malloc_fn = limited_malloc, .free_fn = limited_free};
    for (size_t i = 0; i < 2; ++i) {
        bool success = false;
        for (size_t limit = 0; limit < 100; ++limit) {
            allocation_limit = limit; allocations = 0; cJSON_InitHooks(&hooks);
            memset(output, 0xa5, sizeof output); size_t length = 123;
            efrp_result_t result = efrp_proxy_encode(i == 0 ? EFRP_PROXY_STCP : EFRP_PROXY_HTTP,
                &options[i], "public-proxy", 0, output, sizeof output, &length);
            assert(!outstanding); cJSON_InitHooks(NULL);
            assert(!strcmp(secret, "public-test-secret"));
            if (result == EFRP_OK) { success = true; break; }
            assert(result == EFRP_NO_MEMORY && !length); cleared(output, sizeof output);
        }
        assert(success);
    }
}
int main(void)
{
    type_fields(); xtcp_contract(); invalid_options(); bounds(); owned_inputs(); allocation_failures();
    puts("Proxy registration: wire v2 types, field isolation, domains, capacity, ownership and allocation failures passed");
    return 0;
}
