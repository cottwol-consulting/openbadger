#include <stdio.h>
#include <time.h>
#include <string.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-crypto.h>

#define OID_UNKNOWN     (0)
#define OID_COMMON_NAME (1)
#define OID_DESCRIPTION (2)
#define OID_SERIAL_NUMBER (3)
#define OID_UNIQUE_IDENTIFIER (4)

int find_oid(unsigned char *oid_ptr, int *known_oid);


// arg is filename to dump

int main
  (int argc,
  char *argv [])

{ /* main for ob-cert-dump */

  FILE *certfile;
  OB_CRYPTO_OBJECT certificate;
  OB_CONTEXT *ctx;
  OB_CONTEXT my_openbadger_context;
  int status;
  int status_io;


  ctx = &my_openbadger_context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->verbosity = 3;
  ctx->log = stderr;

  certfile = fopen(argv [1], "r");
  status_io = fread(certificate.raw, sizeof(certificate.raw[0]), sizeof(certificate.raw), certfile);
  certificate.raw_lth = status_io;

  certificate.enc_lth = sizeof(certificate.encoded);
  status = ob_crypto_cert_parse(ctx, &certificate);
  if (status EQUALS ST_OK)
  {
    fprintf(stdout, "%s\n", certificate.encoded);
  };
  return(status);

} /* main for ob-cert-dump */

