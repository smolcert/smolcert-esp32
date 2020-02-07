#include "smolcert.h"

#include <stdlib.h>

void sc_free_cert(smolcert_t* cert) {
  free(cert->issuer);
  free(cert->subject);
  // TODO free extensions
  for(size_t i=0; i<cert->extensions_len; i++) {
    sc_extension_t* ext = &cert->extensions[i];
    free(ext->value);
    free(ext);
  }
  free(cert->extensions);
  free(cert);
}