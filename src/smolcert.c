#include "smolcert.h"
#include <stdlib.h>
#include <sodium.h>
#include <string.h>

void sc_free_cert(smolcert_t* cert);

sc_error_t sc_get_cert(void);
sc_error_t sc_get_curve_public_key(identity_t* cert, uint8_t* curve_pub_key);
sc_error_t sc_get_curve_private_key(privateIdentity_t* cert, uint8_t* curve_priv_key);

sc_error_t sc_new_private_identity(identity_t* cert, uint8_t* priv_key, privateIdentity_t* priv_identity);



void sc_free_cert(identity_t* cert) {
  free(cert->issuer);
  free(cert->subject);
  for(size_t i=0; i<cert->extensions_len; i++) {
    sc_extension_t* ext = &cert->extensions[i];
    free(ext->value);
    free(ext);
  }
  free(cert->extensions);
  free(cert);
}

sc_error_t sc_get_curve_public_key(identity_t* cert, uint8_t* curve_pub_key){
  
  if(crypto_sign_ed25519_pk_to_curve25519(curve_pub_key,cert->public_key) != -1){
    return Sc_Unknown_Error;
  }
  return Sc_No_Error;
}


sc_error_t sc_get_curve_private_key(privateIdentity_t* cert, uint8_t* curve_priv_key){
  if(crypto_sign_ed25519_sk_to_curve25519(curve_priv_key,cert->ed_priv_key) != -1){
    return Sc_Unknown_Error;
  }
  return Sc_No_Error;
}


sc_error_t sc_new_private_identity(identity_t* cert, uint8_t* ed_priv_key, privateIdentity_t* priv_identity){
  priv_identity = (privateIdentity_t*)malloc(sizeof(privateIdentity_t));
  
  if(priv_identity == NULL) return Sc_Unknown_Error;

  priv_identity->identity = cert;
  memcpy(ed_priv_key,priv_identity->ed_priv_key,64);

  return Sc_No_Error;
}

sc_error_t sc_get_cert(void);
