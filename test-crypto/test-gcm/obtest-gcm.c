#include <stdio.h>
#include <string.h>
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <mbedtls/private/gcm.h>
#include <openbadger-common.h>
#include <ob-crypto.h>
#include <ob-crypto-gcm.h>


int main
  (int argc,
  char *argv [])

{ /* main for obtest-gcm */

  unsigned char additional_authenticated_data [1024];
  int auth_data_lth;
  int ciphertext_length;
  unsigned char cleartext [1024];
  int cleartext_length;
  unsigned char decrypted_text [1024];
  OB_CRYPTO_OBJECT encmessage;
  mbedtls_gcm_context key_context;
  OB_CRYPTO_OBJECT key_object;
  int i;
  OB_CRYPTO_CONTEXT_GCM *internal;
  unsigned char iv [96/8 /* OB_CRYPTO_GCM_IV_LENGTH */];
  unsigned char key [OB_CRYPTO_AES256_LENGTH];
  OB_CRYPTO_CONTEXT_GCM my_gcm_context;
  OB_CONTEXT my_openbadger_context;
  OB_CONTEXT *obctx;
  unsigned char output [1024];
  unsigned char saved_ciphertext [1024];
  int status;
  int status_mbed;


  status = ST_OK;
  obctx = &my_openbadger_context;
  memset(obctx, 0, sizeof(*obctx));
  obctx->verbosity = 9;
  obctx->log = stderr;
  memset(&key_object, 0, sizeof(key_object));  
  key_object.internal = &my_gcm_context;
  internal = (OB_CRYPTO_CONTEXT_GCM *)(key_object.internal);

  memset(output, 0, sizeof(output));
memset(key, 0x17, sizeof(key));
memset(iv, 0x41, sizeof(iv));
  auth_data_lth = 0;
memset(decrypted_text, 0, sizeof(decrypted_text));
strcpy((char *)cleartext, "Hello, Galois");
cleartext_length = strlen((char *)cleartext);

  status_mbed = 0;
  mbedtls_gcm_init(&(internal->mbed_context));
  if (status_mbed != 0) { internal->last_mbed_error = status_mbed; status = -101; };
  if (status EQUALS ST_OK)
  {
    mbedtls_gcm_setkey(&key_context, MBEDTLS_CIPHER_ID_AES , key, OB_CRYPTO_AES256_LENGTH*8);
    if (status_mbed != 0) { internal->last_mbed_error = status_mbed; status = -102; };
  };
  if (status EQUALS ST_OK)
  {
    status_mbed = mbedtls_gcm_starts(&key_context,  MBEDTLS_GCM_ENCRYPT, iv, sizeof(iv));
    if (status_mbed != 0) { internal->last_mbed_error = status_mbed; status = -103; };
  };
  if (status EQUALS ST_OK)
  {
    size_t encrypted_length;

    status_mbed = mbedtls_gcm_update(&(internal->mbed_context),
      encmessage.raw, encmessage.raw_lth,
      encmessage.encoded, sizeof(encmessage.encoded), &encrypted_length);
      encmessage.enc_lth = encrypted_length;
    if (status_mbed != 0) { internal->last_mbed_error = status_mbed; status = -104; };
    if (status EQUALS ST_OK)
    {
      status_mbed = mbedtls_gcm_finish(&(internal->mbed_context),
      encmessage.encoded, sizeof(encmessage.encoded),
      &encrypted_length, additional_authenticated_data, auth_data_lth);
      if (status_mbed != 0) { internal->last_mbed_error = status_mbed; status = -104; };
    };
  };
  fprintf(stderr, "Cleartext to be encrypted:\n");
  for (i=0; i<cleartext_length; i++)
  {
    fprintf(stderr, " %02X", cleartext [i]);
  };
  fprintf(stderr, "\n");
  fprintf(stderr, "Ciphertext:\n");
  memcpy(saved_ciphertext, output, cleartext_length);
  ciphertext_length = cleartext_length;
  for (i=0; i<64; i++)
  {
    fprintf(stderr, " %02X", output [i]);
    if (7 EQUALS (i % 8))
      fprintf(stderr, "\n");
  };
  fprintf(stderr, "\n");
  mbedtls_gcm_free(&key_context);

  fprintf(stderr, "Ciphertext to be decrypted:\n");
  for (i=0; i<ciphertext_length; i++)
  {
    fprintf(stderr, " %02X", saved_ciphertext [i]);
  };
  fprintf(stderr, "\n");
fprintf(stderr, "DEBUG: decrypt too\n");
fprintf(stderr, "%ld\n", sizeof(decrypted_text));
#if 0
  mbedtls_gcm_init(&key_context);
  mbedtls_gcm_setkey(&key_context, MBEDTLS_CIPHER_ID_AES , key, OB_CRYPTO_AES256_LENGTH*8);
  mbedtls_gcm_starts(&key_context, MBEDTLS_GCM_DECRYPT, iv, sizeof(iv), additional_authenticated_data, 0);
update ad here too
  mbedtls_gcm_update(&key_context, ciphertext_length, saved_ciphertext, decrypted_text);
    status_mbed = mbedtls_gcm_update(&(internal->mbed_context),
      decmessage.encoded, decmessage.enc_lth,
      decmessage.raw, decrypted_output_size, &(decmessage.raw_lth));
  mbedtls_gcm_finish(&key_context, decrypt_auth_tag, sizeof(decrypt_auth_tag));
#endif
  for (i=0; i<128; i++)
  {
    fprintf(stderr, " %02X", decrypted_text [i]);
  };
  fprintf(stderr, "\n");
  mbedtls_gcm_free(&key_context);

  return(status);
}

