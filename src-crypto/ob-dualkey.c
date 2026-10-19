/*
  ob-dualkey - top level algo-independant public key interface.

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


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-crypto.h>


// message contains ciphertext in blah and cleartext in decoded-blah
int ob_crypto_pk_decrypt
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key,
  OB_CRYPTO_OBJECT *message)

{ /* ob_crypto_pk_decrypt */

  int status;


  status = STOB_CRYPTO_WRONG_ALGO;
  if (key->key_parameters [OB_CKPARM_ALGO] EQUALS OB_CRYPTO_ALG_RSA)
  {
    status = ob_crypto_pk_rsa_decrypt(ctx, key, message);
  };
  return(status);

} /* ob_crypto_pk_decrypt */


int ob_crypto_pk_encrypt
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key,
  OB_CRYPTO_OBJECT *message)

{ /* ob_crypto_pk_encrypt */

  int status;


  status = -10;
  if (key->key_parameters [OB_CKPARM_ALGO] EQUALS OB_CRYPTO_ALG_RSA)
  {
    status = ob_crypto_pk_rsa_encrypt(ctx, key, message);
  };
  return(status);

} /* ob_crypto_pk_encrypt */


/*
thing to geneate key generically
*/


int ob_crypto_pk_initialize
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key)

{ /* ob_crypto_pk_initialize */


  int status;


  if (!(ctx->log))
    status = STOB_NO_LOGGER;

  status = STOB_CRYPTO_WRONG_ALGO;
  if (key->key_parameters [1] EQUALS OB_CRYPTO_ALG_RSA)
  {
    status = ob_crypto_pk_rsa_initialize(ctx, key);
  };
  if (key->key_parameters [1] EQUALS OB_CRYPTO_ALG_EC)
  {
    status = ob_crypto_pk_ec_initialize(ctx, key);
  };

  return(status);

} /* ob_crypto_pk_initialize */


int ob_crypto_sign
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key,
  OB_CRYPTO_OBJECT *tbs,
  OB_CRYPTO_OBJECT *signature)

{ /* ob_crypto_sign */

  int status;


  status = ob_crypto_pk_ec_sign(ctx, key, tbs, signature);

  return(status);

} /* ob_crypto_sign */

