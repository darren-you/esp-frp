# C-only minicrypto source selection from the pinned Picotls checkout.
set(minicrypto_sources
    deps/micro-ecc/uECC.c
    deps/cifra/src/aes.c deps/cifra/src/blockwise.c deps/cifra/src/chacha20.c
    deps/cifra/src/chash.c deps/cifra/src/curve25519.c deps/cifra/src/drbg.c
    deps/cifra/src/hmac.c deps/cifra/src/gcm.c deps/cifra/src/gf128.c deps/cifra/src/modes.c
    deps/cifra/src/poly1305.c deps/cifra/src/sha256.c deps/cifra/src/sha512.c
    lib/cifra.c lib/cifra/x25519.c lib/cifra/chacha20.c lib/cifra/aes128.c
    lib/cifra/aes256.c lib/uecc.c lib/asn1.c lib/ffx.c
    lib/picotls.c lib/hpke.c lib/pembase64.c)
list(TRANSFORM minicrypto_sources PREPEND "${EFRP_PICOTLS_SOURCE_DIR}/")
