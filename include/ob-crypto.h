/*
  openbadger common crypto routine definitions

  (C)Copyright 2026 Cottwol Consulting

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

#define OB_DER_MAX         (32768)

#define OB_CRYPTO_AES128_LENGTH   (128/8)
#define OB_CRYPTO_AES256_LENGTH   (256/8)
#define OB_CRYPTO_SHA256_LENGTH   (256/8)
#define OB_CRYPTO_EC256_X963_LENGTH (1+256/8+256/8)
#define OB_CRYPTO_EC256_PRIV_LENGTH (256/8)

#define OB_CRYPTO_ALG_RSA         (1) // the algorithm
#define OB_CRYPTO_ALG_EC          (2) // the algorithm

//#define OB_AES128_KEY_SIZE (128/8)
//#define OB_RSA2048_KEY_SIZE (2048/8)


#define OB_CRYPTO_CURVE_SECP256R1 (1)
#define OB_CRYPTO_CURVE_BRAINPOOLP256R1 (2)

#define OB_JWK_NIST_P256 "P-256"

#define OB_CRYPTO_SIG_EC (1)
#define OB_CRYPTO_SIG_RSA (2)


#define OB_CPARM_PUBLIC_KEY  (0)
#define OB_CPARM_PRIVATE_KEY (0)

// offsets into key_parameters
#define OB_CKPARM_FORMAT (0) 
#define OB_CKPARM_ALGO (1) 
#define OB_CKPARM_SIZE_CURVE (2)
#define OB_CKPARM_PK_ACTION  (3)
#define OB_CKPARM_PK_PUBPRIV (4)

#define OB_CKPARM_FORMAT_DER     (0)
#define OB_CKPARM_FORMAT_X963    (1)
#define OB_CKPARM_FORMAT_JWK     (2)
#define OB_CKPARM_FORMAT_EC_PRIVATE ( 3)

#define OB_CKPARM_PK_ACTION_NULL (-1)
#define OB_CKPARM_PK_ACTION_GEN  (0)
#define OB_CKPARM_PK_ACTION_LOAD (1)

#define OB_CKPARM_PK_PUBPRIV_PUB  (0)
#define OB_CKPARM_PK_PUBPRIV_PRIV (1)


#define OID_UNKNOWN     (0)
#define OID_COMMON_NAME (1)
#define OID_DESCRIPTION (2)
#define OID_SERIAL_NUMBER (3)
#define OID_UNIQUE_IDENTIFIER (4)

typedef struct ob_crypto_object
{
  unsigned short int state_flags; // 0x01 means initialized
  unsigned long int internal_status;
  void *internal;
  unsigned short int key_parameters [8];
  char description [1024];
  unsigned char aux [OB_DER_MAX]; // also used for IV
  int aux_lth;
  unsigned char encoded [OB_DER_MAX];
  int enc_lth;
  unsigned char raw [OB_DER_MAX]; // also used for key
  int raw_lth;
} OB_CRYPTO_OBJECT;


int ob_crypto_cert_parse(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *certificate);
int ob_crypto_digest_finish(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *digest,
  unsigned char *digest_results, int *digest_length);
int ob_crypto_digest_init(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *digest);
int ob_crypto_digest_update(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *digest,
  unsigned char *message, int message_length);
int ob_crypto_initialize_key_ex(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key);
int ob_crypto_pk_decrypt(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key, OB_CRYPTO_OBJECT *message);
int ob_crypto_pk_ec_encode_x963(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key);
int ob_crypto_pk_ec_generate(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key);
int ob_crypto_pk_encrypt(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *test_rsa_public_key, OB_CRYPTO_OBJECT *test_message);
int ob_crypto_pk_ec_initialize(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key);
int ob_crypto_pk_ec_sign(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key, OB_CRYPTO_OBJECT *tbs, OB_CRYPTO_OBJECT *signature);
int ob_crypto_pk_initialize(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key);
int ob_crypto_pk_rsa_decrypt(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key, OB_CRYPTO_OBJECT *message);
int ob_crypto_pk_rsa_encrypt(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key, OB_CRYPTO_OBJECT *message);
int ob_crypto_pk_rsa_initialize(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key);
int ob_crypto_sign(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key, OB_CRYPTO_OBJECT *tbs, OB_CRYPTO_OBJECT *signature);
int ob_crypto_verify_signature(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *signer_key,
  unsigned char *message, int msg_lth, OB_CRYPTO_OBJECT *signature);

