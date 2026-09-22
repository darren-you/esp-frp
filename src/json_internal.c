// SPDX-License-Identifier: Apache-2.0
#include "json_internal.h"
#include <string.h>

bool efrp_json_utf8(const uint8_t *p, size_t length)
{
    for (size_t i = 0; i < length;) {
        uint32_t cp = p[i++]; unsigned extra = 0; uint32_t minimum = 0;
        if (!cp) return false;
        if (cp < 128) continue;
        if (cp >= 0xc2 && cp <= 0xdf) { extra = 1; minimum = 0x80; cp &= 31; }
        else if (cp >= 0xe0 && cp <= 0xef) { extra = 2; minimum = 0x800; cp &= 15; }
        else if (cp >= 0xf0 && cp <= 0xf4) { extra = 3; minimum = 0x10000; cp &= 7; }
        else return false;
        if (length - i < extra) return false;
        while (extra--) { uint8_t c = p[i++]; if ((c & 0xc0) != 0x80) return false; cp = (cp << 6) | (c & 63u); }
        if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    }
    return true;
}
static bool whitespace(uint8_t c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
static bool bounded_json(const uint8_t *p, size_t length)
{
    /* Bound allocations and recursive parser depth before invoking cJSON.
     * Reject encoded NUL because cJSON exposes strings as C strings. */
    if (!length || length > EFRP_JSON_MAX_BYTES || !efrp_json_utf8(p, length)) return false;
    size_t first = 0;
    while (first < length && whitespace(p[first])) ++first;
    if (first == length || p[first] != '{') return false;
    bool string = false; unsigned depth = 0, punctuation = 0;
    for (size_t i = 0; i < length; ++i) {
        uint8_t c = p[i];
        if (string) {
            if (c < 32) return false;
            if (c == '"') string = false;
            else if (c == '\\') {
                if (++i == length) return false;
                if (p[i] == 'u' && length - i >= 5 && !memcmp(p + i + 1, "0000", 4)) return false;
                if (p[i] < 32) return false;
            }
        } else {
            if (c < 32 && !whitespace(c)) return false;
            if (c == '"') { string = true; ++punctuation; }
            if (c == '{' || c == '[') { if (++depth > 8) return false; ++punctuation; }
            if (c == '}' || c == ']') { if (!depth) return false; --depth; }
            if (c == ',' || c == ':') ++punctuation;
            if (punctuation > 128) return false;
        }
    }
    return !string && !depth;
}
cJSON *efrp_json_parse(const uint8_t *p, size_t length)
{
    if (!bounded_json(p, length)) return NULL;
    const char *end = NULL;
    cJSON *value = cJSON_ParseWithLengthOpts((const char *)p, length, &end, 0);
    if (!value) return NULL;
    const char *limit = (const char *)p + length;
    while (end < limit && whitespace((uint8_t)*end)) ++end;
    if (end != limit || !cJSON_IsObject(value)) { cJSON_Delete(value); return NULL; }
    return value;
}
bool efrp_json_shape(const cJSON *obj, const char *const *allowed, size_t count)
{
    if (!cJSON_IsObject(obj)) return false;
    for (const cJSON *item = obj->child; item; item = item->next) {
        bool found = false;
        if (!item->string) return false;
        for (size_t i = 0; i < count; ++i) if (!strcmp(item->string, allowed[i])) found = true;
        if (!found) return false;
        for (const cJSON *prior = obj->child; prior != item; prior = prior->next)
            if (!strcmp(prior->string, item->string)) return false;
    }
    return true;
}
const cJSON *efrp_json_field(const cJSON *obj, const char *name)
{
    return cJSON_GetObjectItemCaseSensitive(obj, name);
}
const char *efrp_json_string(const cJSON *obj, const char *name)
{
    const cJSON *item = efrp_json_field(obj, name);
    return !item ? "" : cJSON_IsString(item) ? item->valuestring : NULL;
}
bool efrp_json_equals(const cJSON *obj, const char *name, const char *expected)
{
    const char *value = efrp_json_string(obj, name);
    return value && !strcmp(value, expected);
}
