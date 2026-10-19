#include <stdio.h>
#include <time.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>


int main
  (int argc,
  char *argv [])


{ /* main for ob-ec-raw2der */

  FILE *derf;
  unsigned char key_der [16384];
  int key_der_length;
  OB_CONTEXT my_openbadger_context;
  unsigned char raw_key [16384];
  FILE *rawf;
  int status;
  int status_io;


  status = ST_OK;
  rawf = fopen(argv [1], "r");
  status_io = fread(raw_key, sizeof(raw_key[0]), sizeof(raw_key), rawf);
  fclose(rawf);
  fprintf(stderr, "Raw input length %d.\n", status_io);
  key_der_length = sizeof(key_der);
  status = ob_initialize_pubkey_DER(&my_openbadger_context, raw_key, status_io,
    key_der, &key_der_length);
  fprintf(stderr, "DER output length %d.\n", key_der_length);
  derf = fopen(argv[2], "w");
  status_io = fwrite(key_der, sizeof(key_der[0]), key_der_length, derf);
  fclose(derf);
  return(status);
}

