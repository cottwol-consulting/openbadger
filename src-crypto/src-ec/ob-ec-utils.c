/*
  ob-ec-utils - utility routines for EC key manipulation
*/

#include <stdio.h>
#include <time.h>
#include <string.h>

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
#include <ob-crypto-ec.h>

unsigned char ec_public_key_der_skeleton [] =
{
  0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00
  // actual 65 byte key goes after this
};

/*
  ob_initialize_pubkey_DER - convert a raw EC key to DER format.

  assumes SecP256R1 for now...
*/

int ob_initialize_pubkey_DER
  (OB_CONTEXT *ctx,
  unsigned char *key_buffer,
  int kblth,
  unsigned char *marshalled_DER,
  int *marshalled_length)

{ /* ob_intiialize_pubkey_DER */

  memcpy(marshalled_DER, ec_public_key_der_skeleton, sizeof(ec_public_key_der_skeleton));
  memcpy(marshalled_DER+sizeof(ec_public_key_der_skeleton), key_buffer, kblth);
  *marshalled_length = sizeof(ec_public_key_der_skeleton) + kblth;

  return(ST_OK);

} /* ob_initialize_pubkey_DER */


// raw is DER
// encoded is X9.63
// object pre-initialized

int ob_pk_ec_pubkey_DER_to_X963
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *public_key)

{ /* ob_pk_ec_pubkey_DER_to_X963 */

  unsigned char *p;
  int status;
  int tlv_lth;


  status = ST_OK;

  // confirm ec p256r1

  if ((public_key->key_parameters [OB_CKPARM_ALGO] != OB_CRYPTO_ALG_EC) ||
    (public_key->key_parameters [OB_CKPARM_SIZE_CURVE] != OB_CRYPTO_CURVE_SECP256R1))
    status = STOB_CRYPTO_BAD_EC_CURVE;

  if (status EQUALS ST_OK)
  {
    p = public_key->raw;

    // skip outer sequence
    p = p + 2;

    // skip oid sequence
    p = p + 2;

    // skip first oid
    tlv_lth = *(p+1);
    p = p + 2 + tlv_lth;

    // skip second oid
    tlv_lth = *(p+1);
    p = p + 2 + tlv_lth;

    // skip tag=bitstring length header
    tlv_lth = *(p+1);
    p = p + 2;

    // should sanity check
    // skip bits-in-last-octet, which should be zero, and ajust payload
    // length
    p++;
    tlv_lth--;

    // put payload in 'encoded' buffer, it's the X9.62 uncompressed public key
    memcpy(public_key->encoded, p, tlv_lth);
    public_key->enc_lth = tlv_lth;
  };

  return(status);

} /* ob_pk_ec_pubkey_DER_to_X963 */


#if 0
blah ob_pk_ec_privkey_DER_to_X963

blah

int wc_ecc_import_private_key(
    const byte * priv,
    word32 privSz,
    const byte * pub,
    word32 pubSz,
    ecc_key * key
)

#endif

