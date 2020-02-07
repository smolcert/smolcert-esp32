#include "smolcert.h"

void sc_free_cert(smolcert_t* cert) {
  free(cert->issuer);
  free(cert->subject);
  // TODO free extensions
  free(cert);
}