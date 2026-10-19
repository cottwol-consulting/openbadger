/*
  obkex-responder - responds to a key exchange initiator

  assumes the other side will send a public key and consume
  a pubkey/ciphertext response.

  key generation is optional.  If not 
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

{ /* main for obkex-responder */

  OB_TEST_CRYPTO_CONTEXT *ctx;
  OB_CONTEXT my_openbadger_context;
  OB_CRYPTO_OBJECT my_ec_private_key;
  FILE *keyf;
  OB_TEST_CRYPTO_CONTEXT my_test_crypto_context;
  OB_CRYPTO_OBJECT peer_ec_public_key;
  int status;
  int status_io;


  status = ST_OK;
  ctx = &my_test_crypto_context;
  memset(ctx, 0, sizeof(*ctx));
  status = obkex_initialize(ctx);
  if (status EQUALS ST_OK)
  {
    status = obkex_get_settings(ctx);

    memset(&my_openbadger_context, 0, sizeof(my_openbadger_context));
    my_openbadger_context.log = ctx->log;
    my_openbadger_context.verbosity = ctx->verbosity;
  };
  if (status EQUALS ST_OK)
  {
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "openbadger key exchange test responder %s\n", OPENBADGER_VERSION);
      fprintf(ctx->log, "Private key file: %s\n", ctx->my_private_key_filename);
      fprintf(ctx->log, "Generate key: %d\n", ctx->generate_keypair);
    };
  };
  if (status EQUALS ST_OK)
  {
    memset(&peer_ec_public_key, 0, sizeof(peer_ec_public_key));
    peer_ec_public_key.key_parameters [OB_CKPARM_ALGO] =  OB_CRYPTO_ALG_EC;
    peer_ec_public_key.key_parameters [OB_CKPARM_PK_PUBPRIV] =  OB_CKPARM_PK_PUBPRIV_PUB;
    status = obkex_receive_peer_public_key(ctx, &my_openbadger_context, &peer_ec_public_key);
  };
  if (status EQUALS ST_OK)
  {
    memset(&my_ec_private_key, 0, sizeof(my_ec_private_key));
    my_ec_private_key.key_parameters [OB_CKPARM_ALGO] =  OB_CRYPTO_ALG_EC;
    my_ec_private_key.key_parameters [OB_CKPARM_PK_PUBPRIV] =  OB_CKPARM_PK_PUBPRIV_PRIV;

    // have peer's public key.
    // (optionally) generate my key pair

    if (ctx->generate_keypair)
    {
      my_ec_private_key.key_parameters [OB_CKPARM_PK_ACTION] =  OB_CKPARM_PK_ACTION_GEN;
      status = ob_crypto_pk_initialize(&my_openbadger_context, &my_ec_private_key);
    }
    else
    {
      keyf = fopen(ctx->my_private_key_filename, "r");
      if (!keyf)
        status = STKEX_PRIVKEY_LOAD_ERROR;
      if (status EQUALS ST_OK)
      {
        status_io = fread(my_ec_private_key.encoded, sizeof(my_ec_private_key.encoded [0]),
          sizeof(my_ec_private_key.encoded), keyf);
        my_ec_private_key.enc_lth = status_io;
        fclose(keyf);
        my_ec_private_key.key_parameters [OB_CKPARM_PK_ACTION] =  OB_CKPARM_PK_ACTION_LOAD;
        status = ob_crypto_pk_initialize(&my_openbadger_context, &my_ec_private_key);
      };
    };
  };

#if 0
calc shared secret
calc derived key
encrypt message
send my pubkey, ciphertext to the other side
#endif

  if (status != ST_OK)
    fprintf(ctx->log, "openbadger key exchange initiator exit status was %d.\n", status);
  return(status);

} /* main for obkex-responder */

