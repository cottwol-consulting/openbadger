#include <stdio.h>
#include <time.h>
#include <string.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-crypto.h>


char *sample_01_jwk =
"{ \"kty\": \"EC\", \"use\": \"sig\", \"kid\": \"0100DEMOMFGA0001\", \"crv\": \"P-256\", \"x\": \"SWDmpJ3_Y--gxpN-mI9c2DKjZ1B49tkaSGKoXv98yb0\", \"y\": \"DR5pttm9E9xBwZ6eN9sma9f9wRhOGus1uDrZkAe5VTg\" }";


int main
  (int argc,
  char *argv [])

{ /* main for test-ec-jwk */

  OB_CRYPTO_OBJECT imported_key;;
  OB_CONTEXT my_openbadger_context;
  OB_CONTEXT *ob_ctx;
  int status;


  ob_ctx = &my_openbadger_context;
  memset(ob_ctx, 0, sizeof(*ob_ctx));
  ob_ctx->log = stderr;
  ob_ctx->verbosity = 9;
  status = ST_OK;
  imported_key.key_parameters [OB_CKPARM_ALGO] = OB_CRYPTO_ALG_EC;
  imported_key.key_parameters [OB_CKPARM_SIZE_CURVE] = OB_CRYPTO_CURVE_SECP256R1;
  status = ob_crypto_pk_initialize(ob_ctx, &imported_key);

  return(status);

} /* main for test-ec-jwk */

