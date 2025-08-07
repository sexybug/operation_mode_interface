
#ifndef KDF_SM3_H
#define KDF_SM3_H

#include "kdf.h"

void kdf_sm3_init(KDF_CTX *kdf_ctx);

void kdf_sm3_derive_block(KDF_CTX *kdf_ctx, const uint8_t *Z, size_t Z_len, const uint8_t *shared_info, size_t shared_info_len, uint8_t *Ki);

void kdf_sm3_derive(KDF_CTX *kdf_ctx, const uint8_t *Z, size_t Z_len, const uint8_t *shared_info, size_t shared_info_len, uint8_t *key, size_t key_len);

#endif // KDF_SM3_H