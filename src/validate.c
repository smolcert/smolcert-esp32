#include <sodium.h>

#include "smolcert.h"

sc_error_t sc_validate_certificate_signature(uint8_t* cert_buf, size_t cert_len, uint8_t* pub_key) {
  if (cert_len < SMOLCERT_SIGNATURE_LEN + 3) {
    return Sc_Invalid_Format;
  }
  size_t signature_tag_pos = cert_len - (SMOLCERT_SIGNATURE_LEN + 2);
  size_t unsigned_cert_len = cert_len - (SMOLCERT_SIGNATURE_LEN + 1);
  
  if (cert_buf[signature_tag_pos] != 0x58) {
    return Sc_Invalid_Format;
  }
  // Replace the original byte string tag 0x58 0x40 (byte string, length 64) with a simple value
  // (major type 7) and a value of 22, signalling Null
  cert_buf[signature_tag_pos] = (uint8_t)0xF6;

  // Ensure that the last bytes have the necessary length for a signature
  if ((cert_len - (signature_tag_pos + 2)) != SMOLCERT_SIGNATURE_LEN) {
    return Sc_Invalid_Format;
  }
  
  if (crypto_sign_verify_detached((unsigned char*)&cert_buf[signature_tag_pos + 2],
    (unsigned char*)cert_buf, unsigned_cert_len, (unsigned char*)pub_key) != 0) {
   return Sc_Invalid_Signature;
  }
  // Replace the original byte string tag
  cert_buf[signature_tag_pos] = (uint8_t)0x58;
  cert_buf[signature_tag_pos +1] = (uint8_t)0x40;
  return Sc_No_Error;
}