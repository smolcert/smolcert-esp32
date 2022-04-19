#ifndef SMOLCERT_H
#define SMOLCERT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SMOLCERT_PUB_KEY_LEN 32
#define SMOLCERT_PRIV_KEY_LEN 64
#define SMOLCERT_SIGNATURE_LEN 64

#ifdef __cplusplus
extern "C" {
#endif

// sc_error defines error codes for smolcert. These codes are devided into ranges for different categories 
// of errors.
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
  uint64_t version;
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
} smolcert_t, identity_t;

typedef struct privateIdentity {
  smolcert_t *identity;
  uint8_t ed_priv_key[SMOLCERT_PRIV_KEY_LEN];
} privateIdentity_t;

// sc_parse_certificate deserializes a smolcert from the given byte buffer. It will only deserialize
// and ensure a valid format. It will not do any validations.
sc_error_t sc_parse_certificate(const uint8_t* buffer, size_t size, smolcert_t* cert);

// sc_validate_certificate_signature can validate a serialized certificate with a given public key.
// This method does not require to parse the certificate and should be the fastest way to check a
// signature if the certificate exists as byte buffer.
sc_error_t sc_validate_certificate_signature(uint8_t* cert_buf, size_t cert_len, uint8_t* pub_key);

// sc_free_cert frees the memory occupied by a smolcert. It will properly free all strings, lists etc.
// inside the smolcert structure. You should never simply call 'free' on a smolcert as this poses
// the danger of leaking memory.
void sc_free_cert(smolcert_t* cert);
sc_error_t sc_get_cert(void);
sc_error_t sc_get_curve_public_key(identity_t* cert, uint8_t* curve_pub_key);
sc_error_t sc_get_curve_private_key(privateIdentity_t* cert, uint8_t* curve_priv_key);
sc_error_t sc_new_private_identity(identity_t* cert, uint8_t* priv_key, privateIdentity_t* priv_identity);

#ifdef __cplusplus
}
#endif

#endif