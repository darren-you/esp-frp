// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include "picotls/minicrypto.h"
#include "psa/crypto.h"

/* Used by both the Picotls context and minicrypto's X25519 implementation.
 * This void callback cannot report a broken RNG; terminate rather than emit
 * predictable keys. IDF uses its existing PSA/SDK entropy provider. */
void ptls_minicrypto_random_bytes(void *output, size_t length)
{
    if (psa_crypto_init() != PSA_SUCCESS || psa_generate_random(output, length) != PSA_SUCCESS) abort();
}
