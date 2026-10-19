/*
  obkex-initiator - initiate a key exchange process

  assumes the other side is ready to accept a public
  key and respond with a public key, ciphertext pair.

  key generation is optional.  If not sample_initiator_key and
  sample_responder_key will be used.
*/


#include <stdio.h>
#include <time.h>
#include <string.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-crypto.h>
#include <openbadger-version.h>


#include <ob-test-crypto.h>


int main
  (int argc,
  char *argv [])

{ /* main for obkex-initiator */

  OB_TEST_CRYPTO_CONTEXT *ctx;
  OB_CRYPTO_OBJECT ec_private_key;
  OB_CRYPTO_OBJECT ec_public_key;
  FILE *keyf;
  OB_TEST_CRYPTO_CONTEXT my_test_crypto_context;
  OB_CONTEXT my_openbadger_context;
  int status;
  int status_io;


  status = ST_OK;
  ctx = &my_test_crypto_context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->log = stderr;
  ctx->verbosity = 3;
  memset(&my_openbadger_context, 0, sizeof(my_openbadger_context));
  status = obkex_initialize(ctx);
  if (status EQUALS ST_OK)
  {
    status = obkex_get_settings(ctx);
  };
  if (status EQUALS ST_OK)
  {
    my_openbadger_context.log = ctx->log;
    my_openbadger_context.verbosity = ctx->verbosity;

    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "openbadger key exchange test initiator %s\n", OPENBADGER_VERSION);
      fprintf(ctx->log, "Private key file: %s\n", ctx->my_private_key_filename);
      fprintf(ctx->log, "Public key file: %s\n", ctx->my_public_key_filename);
    };
    memset(&ec_private_key, 0, sizeof(ec_private_key));
    ec_private_key.key_parameters [OB_CKPARM_ALGO] =  OB_CRYPTO_ALG_EC;
    ec_private_key.key_parameters [OB_CKPARM_PK_PUBPRIV] =  OB_CKPARM_PK_PUBPRIV_PRIV;
    if (ctx->generate_keypair)
    {
      ec_private_key.key_parameters [OB_CKPARM_PK_ACTION] =  OB_CKPARM_PK_ACTION_GEN;
      status = ob_crypto_pk_initialize(&my_openbadger_context, &ec_private_key);
    }
    else
    {
      keyf = fopen(ctx->my_private_key_filename, "r");
      if (!keyf)
        status = STKEX_PRIVKEY_LOAD_ERROR;
      if (status EQUALS ST_OK)
      {
        status_io = fread(ec_private_key.encoded, sizeof(ec_private_key.encoded [0]),
          sizeof(ec_private_key.encoded), keyf);
        ec_private_key.enc_lth = status_io;
        fclose(keyf);
        ec_private_key.key_parameters [OB_CKPARM_PK_ACTION] =  OB_CKPARM_PK_ACTION_LOAD;
        status = ob_crypto_pk_initialize(&my_openbadger_context, &ec_private_key);
      };
      if (status EQUALS ST_OK)
      {
        keyf = fopen(ctx->my_public_key_filename, "r");
        if (!keyf)
          status = STKEX_PUBKEY_LOAD_ERROR;
      };
      if (status EQUALS ST_OK)
      {
        memset(&ec_public_key, 0, sizeof(ec_public_key));
        ec_public_key.key_parameters [OB_CKPARM_ALGO] =  OB_CRYPTO_ALG_EC;
        ec_public_key.key_parameters [OB_CKPARM_PK_PUBPRIV] =  OB_CKPARM_PK_PUBPRIV_PUB;

        status_io = fread(ec_public_key.encoded, sizeof(ec_public_key.encoded [0]),
          sizeof(ec_public_key.encoded), keyf);
        ec_public_key.enc_lth = status_io;

        ec_private_key.key_parameters [OB_CKPARM_PK_ACTION] =  OB_CKPARM_PK_ACTION_LOAD;
        status = ob_crypto_pk_initialize(&my_openbadger_context, &ec_private_key);
      };
    };
  };
  if (status EQUALS ST_OK)
  {
    status = obkex_send_public_key(ctx, &ec_public_key);
  };
fprintf(ctx->log, "next receive pubkey and ciphertext\n");
#if 0
receive pubkey+ciphertext
calc shared secret
calc derived key
decrypt
#endif

  if (status != ST_OK)
    fprintf(ctx->log, "openbadger key exchange initiator exit status was %d.\n", status);
  return(status);

} /* main for obkex-initiator */

