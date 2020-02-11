#ifndef SMOLCERT_H
#define SMOLCERT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SMOLCERT_PUB_KEY_LEN 32
#define SMOLCERT_SIGNATURE_LEN 64

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sc_error {
  Sc_No_Error = 0,
  Sc_Unknown_Error,

  Sc_Invalid_Format = 128,

  Sc_Validation_Error = 256,
  Sc_Invalid_Signature,
} sc_error_t;

typedef struct sc_validity {
  uint64_t not_before;
  uint64_t not_after;
} sc_validity_t;

typedef struct sc_extension {
  uint64_t oid;
  bool critical;
  uint8_t* value;
  size_t value_len;
} sc_extension_t;

typedef struct smolcert {
  uint64_t serial_number;
  char* issuer;
  size_t issuer_len;
  char* subject;
  size_t subject_len;
  uint8_t public_key[SMOLCERT_PUB_KEY_LEN];
  uint8_t signature[SMOLCERT_SIGNATURE_LEN];
  sc_validity_t validity;
  sc_extension_t* extensions;
  size_t extensions_len;
} smolcert_t;

sc_error_t sc_parse_certificate(const uint8_t* buffer, size_t size, smolcert_t* cert);

sc_error_t sc_validate_certificate_signature(uint8_t* cert_buf, size_t cert_len, uint8_t* pub_key);

void sc_free_cert(smolcert_t* cert);

#ifdef __cplusplus
}
#endif

#endif