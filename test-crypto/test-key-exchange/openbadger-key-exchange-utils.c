#include <stdio.h>
#include <time.h>
#include <string.h>


#include <jansson.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-crypto.h>


#include <ob-test-crypto.h>


/*
  obkex_get_settings - reads settings values from json file

  settings file name is crypto-tester-settings.json

  parameters:
    verbosity - message detail level.  default is 3, debug is 9, silent is 0
    serial-device - what serial port to use.  default is /dev/ttyUSB0
    my-private-key
    my-public-key
*/

int obkex_get_settings
  (OB_TEST_CRYPTO_CONTEXT *ctx)

{ /* obkex_get_settings */

  int i;
  json_t *root;
  int status;
  json_error_t status_json;
  json_t *value;


  status = ST_OK;
  root = json_load_file(CRYPTO_TESTER_SETTINGS_FILE, 0, &status_json);
  if (root)
  {
    value = json_object_get (root, "my-private-key");
    if (json_is_string (value))
    {
      strcpy(ctx->my_private_key_filename, json_string_value(value));
    };
    value = json_object_get (root, "my-public-key");
    if (json_is_string (value))
    {
      strcpy(ctx->my_public_key_filename, json_string_value(value));
    };
    value = json_object_get (root, "verbosity");
    if (json_is_string (value))
    {
      sscanf(json_string_value(value), "%d", &i);
      ctx->verbosity = i;
    };
  };
  return(status);

} /* obkex_get_settings */


int obkex_initialize
  (OB_TEST_CRYPTO_CONTEXT *ctx)

{ /* obkex_initialize */

  ctx->verbosity = 3;
  ctx->log = stderr;
  return(ST_OK);

} /* obkex_initialize */


int obkex_receive_peer_public_key
  (OB_TEST_CRYPTO_CONTEXT *ctx,
  OB_CONTEXT *obctx,
  OB_CRYPTO_OBJECT *peer_public_key)

{
  // read in minimal pubkey ec bytes
  // stuff it in the object, import if necessary, init
  return(-1);
}



int obkex_send_public_key
  (OB_TEST_CRYPTO_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *ec_public_key)

{
  return(-1);
}


