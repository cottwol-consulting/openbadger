/*
  eac crypto routines for EC based on WolfSSL
*/


#include <stdio.h>
#include <time.h>
#include <stdlib.h>


#include <jansson.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>

#define WOLFSSL_USE_OPTIONS_H
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>


#include <openbadger-common.h>
#include <ob-crypto.h>
#include <ob-encode.h>

#include <ob-crypto-ec.h>


/*
  ob_crypto_pk_ec_encode_x963

  returns x9.63 encoding in key->encoded
*/
int
  ob_crypto_pk_ec_encode_x963
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key)

{ /* ob_crypto_pk_ec_encode_x963 */

  word32 encoded_length;
  OB_CRYPTO_CONTEXT_EC *internal;
  int status;
  int status_wolfssl;


  status = ST_OK;
  internal = key->internal;
  encoded_length = sizeof(key->encoded);
  status_wolfssl = wc_ecc_export_x963(&(internal->key), key->encoded, &encoded_length);
  if (status_wolfssl != 0)
  {
    status = STOB_CRYPTO_SUBSYSTEM;
    internal->last_wolfssl_error = status_wolfssl;
  };
  if (status EQUALS ST_OK)
    key->enc_lth = encoded_length;
  return(status);
  
} /* ob_crypto_pk_ec_encode_x963 */


/*
  ob_crypto_pk_ec_initialize - initialize an EC key

  Inputs:
    openbadger context
    key openbadger object
      key parameters [OB_CKPARM_FORMAT] is the format.
      encoded field is DER, X9.63 compressed, or JWK

  for JWK supports SecP256R1 (NIST) only.
todo: add brainpool

for ec private init it reads the encoded as der and unwinds the raw private key component into raw
*/
int
  ob_crypto_pk_ec_initialize
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key)

{ /* ob_crypto_pk_ec_initialize */


  char d_decoded [32768];
  int d_lth;
  word32 der_index;
  OB_CRYPTO_CONTEXT_EC *internal;
  json_t *root;
  int status;
  json_error_t status_json;
  int status_wolfssl;
  json_t *value;
  char x_decoded [32768];
  int x_lth;
  char y_decoded [32768];
  int y_lth;


  status = ST_OK;
  if (!(ctx->log))
    status = STOB_NO_LOGGER;
  if (status EQUALS ST_OK)
  {
    if (key->internal)
      status = STOB_MALLOC; // better be empty if we're in the init code
  };
  if (status EQUALS ST_OK)
    if (key->key_parameters [OB_CKPARM_ALGO] != OB_CRYPTO_ALG_EC)
      status = STOB_CRYPTO_WRONG_ALGO;
  if (status EQUALS ST_OK)
  {
    internal = malloc(sizeof(*internal));
    if (!internal)
      status = STOB_MALLOC;
  };
  if (status EQUALS ST_OK)
  {
    key->internal = internal;
    internal->sigalg = key->key_parameters [OB_CKPARM_ALGO];
    internal->alg_param_1 = key->key_parameters [OB_CKPARM_SIZE_CURVE];

    switch(key->key_parameters [OB_CKPARM_FORMAT])
    {
    case OB_CKPARM_FORMAT_DER:
      der_index = 0;
{
  FILE *f;
  f = fopen("temp.der", "w");
  fwrite(key->encoded, sizeof(unsigned char), key->enc_lth, f);
  fclose(f);
}
      status_wolfssl = wc_EccPublicKeyDecode(key->encoded, &der_index, &(internal->key), key->enc_lth);
      if (status_wolfssl != 0)
      {
        status = STOB_CRYPTO_SUBSYSTEM;
        internal->last_wolfssl_error = status_wolfssl;
      };
      break;
    /*
      extract the raw private key (to raw buffer) from the encoded buffer DER-encoded

      manually walks through DER data structure.  knows a DER encoded EC private key
      length.
    */
    case OB_CKPARM_FORMAT_EC_PRIVATE:
      {
        unsigned char *p;
        p = key->encoded;
        if (key->enc_lth < 121)
          status = STOB_CRYPTO_PRIV_IMPORT;
        if (key->key_parameters [OB_CKPARM_SIZE_CURVE] != OB_CRYPTO_CURVE_SECP256R1)
          status = STOB_CRYPTO_PRIV_IMPORT;
        if (status EQUALS ST_OK)
        {
          // skip 'sequence'
          p = p + 2;

          // skip 'integer'
          p = p + 3;

          /*
            should be at 'octet string' length 0x20.
            sanity check and skip to private key payload
          */
          if (*p != DER_TAG_OCTETSTRING)
            status = STOB_CRYPTO_PRIV_IMPORT;
        };
        if (status EQUALS ST_OK)
        {
          p++; // tag was good
          if (*p != 0x20)
            status = STOB_CRYPTO_PRIV_IMPORT;
        };
        if (status EQUALS ST_OK)
        {
          p++; // length was good; 
          memcpy(key->raw, p, OB_CRYPTO_EC256_PRIV_LENGTH); 
          key->raw_lth = OB_CRYPTO_EC256_PRIV_LENGTH;
        };
      };
      break;
    case OB_CKPARM_FORMAT_JWK:
      root = json_loads((char *)(key->encoded), 0, &status_json);
      if (root)
      {
        status_wolfssl = wc_ecc_init(&(internal->key));
        if (status_wolfssl)
        {
          status = STOB_CRYPTO_ERROR;
          internal->last_wolfssl_error = status_wolfssl;
        };
        if (status EQUALS ST_OK)
        {
          value = json_object_get (root, "crv");
          if (json_is_string (value))
          {
            if (!strcmp(json_string_value(value), OB_JWK_NIST_P256))
              status = STOB_UNSUPPORTED_JWK_CURVE;
            else
            {
              status_wolfssl = wc_ecc_set_curve(&(internal->key), 32, ECC_SECP256R1);
              if (status_wolfssl)
              {
                status = STOB_CRYPTO_ERROR;
                internal->last_wolfssl_error = status_wolfssl;
              };
            };
          };
        };
        if (status EQUALS ST_OK)
        {
          value = json_object_get (root, "d");
          if (json_is_string (value))
          {
            d_lth = sizeof(d_decoded);
            status= ob_base64url_to_binary(ctx, (char *)json_string_value(value),
              (unsigned char *)d_decoded, &d_lth);
          };
        };
        if (status EQUALS ST_OK)
        {
          value = json_object_get (root, "x");
          if (json_is_string (value))
          {
            x_lth = sizeof(x_decoded);
            status = ob_base64url_to_binary(ctx, (char *)json_string_value(value),
              (unsigned char *)x_decoded, &x_lth);
          };
        };
        if (status EQUALS ST_OK)
        {
          value = json_object_get (root, "y");
          if (json_is_string (value))
          {
            y_lth = sizeof(d_decoded);
            status = ob_base64url_to_binary(ctx, (char *)json_string_value(value),
              (unsigned char *)y_decoded, &y_lth);
          };
        };
        if (status EQUALS ST_OK)
        {
          status_wolfssl = wc_ecc_import_raw_ex(&(internal->key),
            x_decoded, y_decoded, d_decoded, ECC_SECP256R1);
          if (status_wolfssl)
          {
            status = STOB_CRYPTO_ERROR;
            internal->last_wolfssl_error = status_wolfssl;
          };
        };
      };
      break;
    case OB_CKPARM_FORMAT_X963:
      status_wolfssl = wc_ecc_import_x963(key->raw, key->raw_lth, &(internal->key));
      if (status_wolfssl != 0)
      {
        status = STOB_CRYPTO_SUBSYSTEM;
        internal->last_wolfssl_error = status_wolfssl;
      };
      break;
    };
  };
  return(status);

} /* ob_crypto_pk_ec_initialize */


int ob_crypto_pk_ec_sign
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key,
  OB_CRYPTO_OBJECT *tbs,
  OB_CRYPTO_OBJECT *signature)

{ /* ob_crypto_pk_ec_sign */

  OB_CRYPTO_CONTEXT_EC *internal;
  WC_RNG rng;
  int status;
  int status_wolfssl;


  status = ST_OK;
  internal = key->internal;
  wc_InitRng(&rng);
  status_wolfssl = wc_SignatureGenerate
    (WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC, tbs->raw, tbs->raw_lth,
    signature->encoded, (word32 *)&(signature->enc_lth),
    &(internal->key), sizeof(internal->key), &rng);
  if (status_wolfssl != 0)
  {
    status = STOB_CRYPTO_SUBSYSTEM;
    internal->last_wolfssl_error = status_wolfssl;
  };
  return(status);

} /* ob_crypto_pk_ec_sign */


// this assumes it's SHA256, it does the hash operation,
// pass it the original message

// expects signer_key to be initialized with internal context
// including sigalg
// including curve type
// signer key raw is key
// signature encoded is DER encoded signature

int ob_crypto_verify_signature
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *signer_key,
  unsigned char *message,
  int msg_lth,
  OB_CRYPTO_OBJECT *signature)

{ /* ob_crypto_verify_signature */

  OB_CRYPTO_CONTEXT_EC *internal;
  enum wc_SignatureType sig_type;
  int status;
  int status_wolfssl;


  status = ST_OK;
  if (!(ctx->log))
    status = STOB_NO_LOGGER;
  if (status EQUALS ST_OK)
  {
    if (!(signer_key->internal))
      status = STOB_MALLOC;
  };
  if (status EQUALS ST_OK)
  {
    internal = signer_key->internal;

    if (internal->sigalg != OB_CRYPTO_ALG_EC)
      status = STOB_CRYPTO_UNKNOWN_KEYTYPE;
    if (status EQUALS ST_OK)
    {
      // it's an EC signature

      sig_type = WC_SIGNATURE_TYPE_ECC;

      switch(internal->alg_param_1)
      {
      default:
        status = STOB_CRYPTO_BAD_EC_CURVE;
        break;
      case OB_CRYPTO_CURVE_SECP256R1:
      case OB_CRYPTO_CURVE_BRAINPOOLP256R1:
        if (signature->enc_lth EQUALS 0)
          status = STOB_CRYPTO_BAD_ENC_SIG;
        break;
      };
    };
  };
  if (status EQUALS ST_OK)
  {
    enum wc_HashType hash_type;

hash_type = WC_HASH_TYPE_SHA256;
    if (ctx->verbosity > 3)
    {
      int i;


      fprintf(ctx->log, "DEBUG: verify: mlth %d slth %d hash %d sig %d\n",
        msg_lth, signature->raw_lth, hash_type, sig_type);

      fprintf(stderr, "msg (%d.)\n", msg_lth);
      for(i=0; i<msg_lth; i++) fprintf(stderr, " %02X", message [i]);
      fprintf(stderr, "\n");
      fprintf(stderr, "sig (%d.)\n", signature->raw_lth);
      for(i=0; i<signature->raw_lth; i++) fprintf(stderr, " %02X", signature->raw [i]);
      fprintf(stderr, "\n");

      fprintf(stderr, "DEBUG: before wc_SignatureVerify hash...\n");
    };

    // uses DER-encoded signature

    status_wolfssl = wc_SignatureVerify(hash_type, sig_type,
      message, msg_lth, signature->encoded, signature->enc_lth, &(internal->key), sizeof(internal->key));
    if (status_wolfssl != 0)
    {
      internal->last_wolfssl_error = status_wolfssl;
      status = STOB_CRYPTO_VERIFY_FAIL;
    };
  };
  return(status);

} /* ob_crypto_verify_signature */

