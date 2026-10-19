#define CRYPTO_TESTER_SETTINGS_FILE "openbadger-settings.json"

typedef struct ob_test_crypto
{
  int verbosity;
  FILE *log;
  char serial_device [1024];
  char my_private_key_filename [1024];
  char my_public_key_filename [1024];
  int generate_keypair;
} OB_TEST_CRYPTO_CONTEXT;

#define STKEX_PRIVKEY_LOAD_ERROR (1)
#define STKEX_PUBKEY_LOAD_ERROR  (2)

int obkex_get_settings(OB_TEST_CRYPTO_CONTEXT *ctx);
int obkex_initialize(OB_TEST_CRYPTO_CONTEXT *ctx);
int obkex_receive_peer_public_key(OB_TEST_CRYPTO_CONTEXT *ctx, OB_CONTEXT *obctx, OB_CRYPTO_OBJECT *peer_public_key);
int obkex_send_public_key(OB_TEST_CRYPTO_CONTEXT *ctx, OB_CRYPTO_OBJECT *public_key);


