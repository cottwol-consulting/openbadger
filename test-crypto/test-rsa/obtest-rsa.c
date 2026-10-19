/*
  obtest-rsa - RSA cryptography examples

  Use test-generate-rsa-keypair.sh to create a key pair.  It will
  create sample_pubkey.der and sample_privkey.der.

  Creates ciphertext.bin by encrypting the test message with the public key.
  The test message is "abcd1234".


  Copyright 2026 Cottwol Consulting

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/


#include <stdio.h>
#include <string.h>
#include <time.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <openbadger-version.h>
#include <ob-crypto.h>

int main
  (int argc,
  char *argv [])

{ /* main for obtest-rsa */

  OB_CONTEXT *ctx;
  FILE *keyf;
  OB_CONTEXT my_openbadger_context;
  int status;
  int status_io;
  OB_CRYPTO_OBJECT test_message;
  OB_CRYPTO_OBJECT test_rsa_private_key;
  OB_CRYPTO_OBJECT test_rsa_public_key;
int switch_generate=0;
int switch_load=1;
int switch_ciphertext_public=1;
char param_public_key_filename [1024];
char param_private_key_filename [1024];


  status = ST_OK;
  ctx = &my_openbadger_context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->log = stderr;
  ctx->verbosity = 9;
strcpy(param_public_key_filename, "sample_pubkey.der");
strcpy(param_private_key_filename, "sample_privkey.der");

  if (status EQUALS ST_OK)
  {
    if (switch_generate)
    {
      status = -1;
      fprintf(stderr, "key generation not implemented.\n");
    };
    if (switch_load)
    {
      keyf = fopen(param_public_key_filename, "r");
      if (!keyf)
        status = -3;
      if (status EQUALS ST_OK)
      {
        memset(&test_rsa_public_key, 0, sizeof(test_rsa_public_key));
        status_io = fread(test_rsa_public_key.encoded, sizeof(test_rsa_public_key.encoded [0]),
          sizeof(test_rsa_public_key.encoded), keyf);
        test_rsa_public_key.enc_lth = status_io;
        fclose(keyf);

        test_rsa_public_key.key_parameters [OB_CKPARM_ALGO] =  OB_CRYPTO_ALG_RSA;
        test_rsa_public_key.key_parameters [OB_CKPARM_PK_PUBPRIV] =  OB_CKPARM_PK_PUBPRIV_PUB;
        test_rsa_public_key.key_parameters [OB_CKPARM_PK_ACTION] =  OB_CKPARM_PK_ACTION_LOAD;
        status = ob_crypto_pk_initialize(ctx, &test_rsa_public_key);
      };
      if (status EQUALS ST_OK)
      {
        keyf = fopen(param_private_key_filename, "r");
        if (!keyf)
          status = -12;
        if (status EQUALS ST_OK)
        {
          memset(&test_rsa_private_key, 0, sizeof(test_rsa_private_key));
          status_io = fread(test_rsa_private_key.encoded, sizeof(test_rsa_private_key.encoded [0]),
            sizeof(test_rsa_private_key.encoded), keyf);
          test_rsa_private_key.enc_lth = status_io;
          fclose(keyf);

          test_rsa_private_key.key_parameters [OB_CKPARM_ALGO] =  OB_CRYPTO_ALG_RSA;
          test_rsa_private_key.key_parameters [OB_CKPARM_PK_PUBPRIV] =  OB_CKPARM_PK_PUBPRIV_PRIV;
          test_rsa_private_key.key_parameters [OB_CKPARM_PK_ACTION] =  OB_CKPARM_PK_ACTION_LOAD;
          status = ob_crypto_pk_initialize(ctx, &test_rsa_private_key);
        };
      };
    };
  };

  if (status EQUALS ST_OK)
  {
    memset(&test_message, 0, sizeof(test_message));
    strcpy((char *)(test_message.raw), "abcd1234");
    test_message.raw_lth = strlen((char *)(test_message.raw));
    status = ob_crypto_pk_encrypt(ctx, &test_rsa_public_key, &test_message);
    if (status EQUALS ST_OK)
    {
      fprintf(stderr, "Encrypted buffer:\n");
      ob_dump_buffer(ctx, test_message.encoded, test_message.enc_lth, 0);
{
  FILE *f;
  f = fopen("ciphertext.bin", "w");
  fwrite(test_message.encoded, sizeof(test_message.encoded[0]),
    test_message.enc_lth, f);
}
    };
  };

  if (status EQUALS ST_OK)
  {
    if (switch_ciphertext_public)
    {
      // clear out plaintext so we know we got an answer
      memset(test_message.raw, 0, sizeof(test_message.raw));
      fprintf(stderr, "Decrypt using public key...\n");
      status = ob_crypto_pk_decrypt(ctx, &test_rsa_private_key, &test_message);
      if (status EQUALS ST_OK)
      {
        fprintf(stderr, "Decrypted buffer:\n");
        ob_dump_buffer(ctx, test_message.raw, test_message.raw_lth, 0);
      };
    };
  };

  if (status != ST_OK)
    fprintf(stderr, "obtest-rsa return status was %d.\n", status);

  return(status);

} /* main for obtest-rsa */

