/*
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
#include <time.h>
#include <stdlib.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>

#define WOLFSSL_USE_OPTIONS_H
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/rsa.h>
//#include <wolfssl/wolfcrypt/asn_public.h>


#include <openbadger-common.h>
#include <ob-crypto.h>
#include <ob-crypto-rsa.h>


/*
  ob_crypto_pk_rsa_initialize - initialize an RSA key

  Inputs:
    openbadger context
    key openbadger object
      encoded field is the DER of the signer key
*/
int
  ob_crypto_pk_rsa_initialize
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key)

{ /* ob_crypto_pk_rsa_initialize */

  int action;
  word32 der_index;
  OB_CRYPTO_CONTEXT_RSA *internal;
  int status;
  int status_wolfssl;


  status = ST_OK;
  if (!(ctx->log))
    status = STOB_NO_LOGGER;
  if (status EQUALS ST_OK)
  {
    if (key->internal)
      status = STOB_MALLOC; // better be empty if we're in the init code
  };
  if (key->key_parameters [OB_CKPARM_ALGO] != OB_CRYPTO_ALG_RSA)
    status = STOB_CRYPTO_WRONG_ALGO;
  if (status EQUALS ST_OK)
  {
    internal = malloc(sizeof(*internal));
    if (!internal)
      status = STOB_MALLOC;
  };
  if (status EQUALS ST_OK)
    key->internal = internal;
  if (status EQUALS ST_OK)
  {
    status_wolfssl = wc_InitRsaKey(&(internal->key), NULL);
  };
  if (status EQUALS ST_OK)
  {
    action = OB_CKPARM_PK_ACTION_NULL;
    if (key->key_parameters [OB_CKPARM_PK_ACTION] EQUALS OB_CKPARM_PK_ACTION_LOAD)
      action = OB_CKPARM_PK_ACTION_LOAD;
    if (action EQUALS OB_CKPARM_PK_ACTION_NULL)
      status = -8;
  };
  if ((status EQUALS ST_OK) && (action EQUALS OB_CKPARM_PK_ACTION_LOAD))
  {
    switch(key->key_parameters [OB_CKPARM_FORMAT])
    {
    case OB_CKPARM_FORMAT_DER:
      status = STOB_CRYPTO_BAD_KEY_TYPE;

      wc_InitRng(&(internal->rng));
      if (ctx->verbosity > 3)
        fprintf(ctx->log, "object rng initialized.\n");

      if (key->key_parameters [OB_CKPARM_PK_PUBPRIV] EQUALS OB_CKPARM_PK_PUBPRIV_PUB)
      {
        // we got asked to load a DER-encoded public RSA key
        der_index = 0; // offset into buffer
        status_wolfssl = wc_RsaPublicKeyDecode(key->encoded, &der_index, &(internal->key), key->enc_lth);
        if (status_wolfssl != 0)
        {
          status = STOB_CRYPTO_SUBSYSTEM;
          internal->last_wolfssl_error = status_wolfssl;
        }
        else
        {
          status = ST_OK;
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "RSA Public DER Decode good, %d. octets consumed.\n", der_index);
        };
      };
      if (key->key_parameters [OB_CKPARM_PK_PUBPRIV] EQUALS OB_CKPARM_PK_PUBPRIV_PRIV)
      {
        // we got asked to load a DER-encoded private RSA key
        der_index = 0; // offset into buffer
        status_wolfssl = wc_RsaPrivateKeyDecode(key->encoded, &der_index, &(internal->key), key->enc_lth);
        if (status_wolfssl != 0)
        {
          status = STOB_CRYPTO_SUBSYSTEM;
          internal->last_wolfssl_error = status_wolfssl;
        }
        else
        {
          status = ST_OK;
          if (ctx->verbosity > 3)
            fprintf(ctx->log, "RSA Private DER Decode good, %d. octets consumed.\n", der_index);
        };
      };
      break;
    default:
      status = -5;
      break;
    };
  };
  return(status);

} /* ob_crypto_pk_rsa_initialize */


int ob_crypto_pk_rsa_decrypt
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key,
  OB_CRYPTO_OBJECT *message)

{ /* ob_crypto_pk_rsa_decrypt */

  OB_CRYPTO_CONTEXT_RSA *internal;
  int status;
  int status_wolfssl;


  status = ST_OK;
  if (!(ctx->log))
    status = STOB_NO_LOGGER;
  if (status EQUALS ST_OK)
  {
    if (!(key->internal))
      status = STOB_MALLOC; // better be there
  };
  if (status EQUALS ST_OK)
  {
    if (key->key_parameters [OB_CKPARM_ALGO] != OB_CRYPTO_ALG_RSA)
      status = STOB_CRYPTO_WRONG_ALGO;
  };
  if (status EQUALS ST_OK)
  {
    internal = key->internal;
internal->key.rng = &(internal->rng);

    status_wolfssl = wc_RsaPrivateDecrypt_ex(message->encoded, message->enc_lth,
      message->raw, sizeof(message->raw), &(internal->key), WC_RSA_PKCSV15_PAD,
      WC_MGF1NONE, 0, NULL, 0);
    if (status_wolfssl <= 0)
    {
      status = STOB_CRYPTO_SUBSYSTEM;
      internal->last_wolfssl_error = status_wolfssl;
    }
    else
    {
      message->raw_lth = status_wolfssl;
    };
  };
  return(status);

} /* ob_crypto_pk_rsa_decrypt */


int ob_crypto_pk_rsa_encrypt
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key,
  OB_CRYPTO_OBJECT *message)

{ /* ob_crypto_pk_rsa_encrypt */

  OB_CRYPTO_CONTEXT_RSA *internal;
  int status;
  int status_wolfssl;


  status = ST_OK;
  if (!(ctx->log))
    status = STOB_NO_LOGGER;
  if (status EQUALS ST_OK)
  {
    if (!(key->internal))
      status = STOB_MALLOC; // better be empty if we're in the init code
  };
  if (status EQUALS ST_OK)
  {
    if (key->key_parameters [OB_CKPARM_ALGO] != OB_CRYPTO_ALG_RSA)
      status = -6;
  };
  if (status EQUALS ST_OK)
  {
    internal = key->internal;


    message->enc_lth = sizeof(message->encoded);
    status_wolfssl = wc_RsaPublicEncrypt_ex(message->raw, message->raw_lth,
      message->encoded, message->enc_lth, &(internal->key), &(internal->rng), WC_RSA_PKCSV15_PAD,
      WC_MGF1NONE, 0, NULL, 0);
    if (status_wolfssl <= 0)
    {
      status = STOB_CRYPTO_SUBSYSTEM;
      internal->last_wolfssl_error = status_wolfssl;
    }
    else
    {
      message->enc_lth = status_wolfssl;
    };
  };
  return(status);

} /* ob_crypto_pk_rsa_encrypt */

