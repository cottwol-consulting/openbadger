#include <stdio.h>
#include <time.h>
#include <string.h>
#include <getopt.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>


#include <openbadger-common.h>
#include <ob-crypto.h>
#include <ob-crypto-ec.h>

#define TEST_VERSION "0.00"

typedef struct test_context
{
  int option_switch;
  int verbosity;
  int reader_index;
  int command;
  int curve;
  int key_format;
  FILE *log;
  char settings_filename [1024];
  char key_filename [1024];
  char message_filename [1024];
  char signature_filename [1024];
} TEST_CONTEXT;


TEST_CONTEXT my_test_context;
#define OPT_NOOP      (0)
#define OPT_READER    (1)
#define OPT_SETTINGS  (2)
#define OPT_VERBOSITY (3)
#define OPT_HELP      (4)
#define OPT_CURVE     (5)
#define OPT_KEY       (6)
#define OPT_COMMAND   (7)
#define OPT_MESSAGE   (8)
#define OPT_SIGNATURE (9)
struct option longopts [] = {
  {"command", 0, &(my_test_context.option_switch), OPT_COMMAND},
  {"curve", 0, &(my_test_context.option_switch), OPT_CURVE},
  {"help", 0, &(my_test_context.option_switch), OPT_HELP},
  {"key", required_argument, &(my_test_context.option_switch), OPT_KEY},
  {"message", required_argument, &(my_test_context.option_switch), OPT_MESSAGE},
  {"reader", required_argument, &(my_test_context.option_switch), OPT_READER},
  {"settings", required_argument, &(my_test_context.option_switch), OPT_SETTINGS},
  {"signature", required_argument, &(my_test_context.option_switch), OPT_SIGNATURE},
  {"verbosity", required_argument, &(my_test_context.option_switch), OPT_VERBOSITY},
  {0, 0, 0, 0}
};

int ob_key_import_public(OB_CONTEXT *ctx, unsigned char *buffer, int buffer_length, OB_CRYPTO_OBJECT *key);
#define CMD_TEST_KEY_IMPORT_PUBLIC           (0)
#define CMD_TEST_IMPORT_AND_VERIFY           (1)
#define CMD_TEST_KEY_IMPORT_PRIVATE          (2)
//#define CMD_TEST_IMPORT_AND_VERIFY_BRAINPOOL (3)
int initialize_test(TEST_CONTEXT *ctx, int argc, char *argv []);
int load_public_key(TEST_CONTEXT *ctx, char *filename, unsigned char *buffer, int *buffer_length);


char optstring [OB_STRING_MAX];


int main
  (int argc,
  char *argv [])

{ /* test-ec */

  OB_CRYPTO_OBJECT ec_public_key;
  unsigned char message [1024];
  int message_length;
  FILE *msgfile;
  OB_CONTEXT my_openbadger_context;
  OB_CONTEXT *ob_ctx;
  FILE *sigfile;
  OB_CRYPTO_OBJECT signature;
  int status;


  status = ST_OK;
  memset(&my_test_context, 0, sizeof(my_test_context));
  status = initialize_test(&my_test_context, argc, argv);
  if (status EQUALS ST_OK)
  {
    ob_ctx = &my_openbadger_context;
    memset(ob_ctx, 0, sizeof(*ob_ctx));
    ob_ctx->log = my_test_context.log;
    ob_ctx->verbosity = my_test_context.verbosity;
    memset(&ec_public_key, 0, sizeof(ec_public_key));

    fprintf(my_test_context.log,
"Test EC Cryptographic Operations %s\n", TEST_VERSION);
    fprintf(my_test_context.log,
"   Message file %s\n", my_test_context.message_filename);
    fprintf(my_test_context.log,
" Signature file %s\n", my_test_context.signature_filename);
    fprintf(my_test_context.log,
"Public Key file %s\n", my_test_context.key_filename);
    fprintf(my_test_context.log,
"          Curve %d\n", my_test_context.curve);
    fprintf(my_test_context.log,
"      Verbosity %d.\n", my_test_context.verbosity);
    fprintf(my_test_context.log,
"        Command %d\n", my_test_context.command);

  switch(my_test_context.command)
  {
  case CMD_TEST_KEY_IMPORT_PUBLIC:
    ec_public_key.raw_lth = sizeof(ec_public_key.raw);
    status = load_public_key(&my_test_context, my_test_context.key_filename, ec_public_key.raw, &(ec_public_key.raw_lth));
    if (status EQUALS ST_OK)
    {
      ec_public_key.key_parameters [OB_CKPARM_ALGO] = OB_CRYPTO_ALG_EC;
      ec_public_key.key_parameters [OB_CKPARM_SIZE_CURVE] = OB_CRYPTO_CURVE_SECP256R1;
      status = ob_crypto_pk_initialize(ob_ctx, &ec_public_key);
    };
    break;
  case CMD_TEST_IMPORT_AND_VERIFY:
    if (my_test_context.verbosity > 3)
      fprintf(my_test_context.log, "-- Test: Import and Verify\n");
    ec_public_key.raw_lth = sizeof(ec_public_key.raw);
    status = load_public_key(&my_test_context, my_test_context.key_filename, ec_public_key.raw, &(ec_public_key.raw_lth));
    if (status EQUALS ST_OK)
    {
      ec_public_key.key_parameters [OB_CKPARM_ALGO] = OB_CRYPTO_ALG_EC;
      ec_public_key.key_parameters [OB_CKPARM_SIZE_CURVE] = OB_CRYPTO_CURVE_SECP256R1;
      status = ob_crypto_pk_initialize(ob_ctx, &ec_public_key);
    };
    if (my_test_context.verbosity > 3)
      fprintf(my_test_context.log, "-- load public key status %d\n", status);

    if (status EQUALS ST_OK)
    {
      // fetch signed message
      msgfile = fopen(my_test_context.message_filename, "r");
      if (msgfile != NULL)
      {
        message_length = fread(message, sizeof(message [0]), sizeof(message), msgfile);
        fclose(msgfile);
      }
      else
      {
        if (my_test_context.verbosity > 3)
          fprintf(my_test_context.log, "-- failed to open message file %s\n", my_test_context.message_filename);
        status = -2;
      };
    };
    if (status EQUALS ST_OK)
    {
      if (my_test_context.verbosity > 3)
        fprintf(ob_ctx->log, "Message imported from file %s (length %d.)\n", "message.bin", message_length);

      // fetch signature
      sigfile = fopen(my_test_context.signature_filename, "r");
      if (sigfile != NULL)
        signature.raw_lth = fread(signature.raw, sizeof(signature.raw [0]), sizeof(signature.raw), sigfile);
    };

    if (status EQUALS ST_OK)
    {
      fprintf(ob_ctx->log, "Signature imported from file %s (length %d.)\n", "signature.bin", signature.raw_lth);

      // verify signature

fprintf(stderr, "DEBUG add sig import\n");
      status = ob_crypto_verify_signature(ob_ctx, &ec_public_key, message, message_length,
        &signature);
    };
    if (status EQUALS ST_OK)
      fprintf(ob_ctx->log, "SIGNATURE VERIFIED\n");
    break;
#if 0
  case CMD_TEST_IMPORT_AND_VERIFY_BRAINPOOL:
    ec_public_key.raw_lth = sizeof(ec_public_key.raw);
    status = load_public_key(&my_test_context, my_test_context.key_filename, ec_public_key.raw, &(ec_public_key.raw_lth));
    if (status EQUALS ST_OK)
      status = ob_crypto_initialize_key(ob_ctx, &ec_public_key, OB_CRYPTO_ALG_EC, OB_CRYPTO_CURVE_BRAINPOOLP256R1);

    if (status EQUALS ST_OK)
    {
      FILE *msgfile;

      // fetch signed message
      msgfile = fopen("message.bin", "r");
      if (msgfile != NULL)
        message_length = fread(message, sizeof(message [0]), sizeof(message), msgfile);
    };
    if (status EQUALS ST_OK)
    {
      FILE *sigfile;

      fprintf(ob_ctx->log, "Message imported from file %s (length %d.)\n", "message.bin", message_length);

      // fetch signature
      sigfile = fopen("signature.bin", "r");
      if (sigfile != NULL)
        signature.raw_lth = fread(signature.raw, sizeof(signature.raw [0]), sizeof(signature.raw), sigfile);
    };

    if (status EQUALS ST_OK)
    {
      fprintf(ob_ctx->log, "Signature imported from file %s (length %d.)\n", "signature.bin", signature.raw_lth);

      // verify signature

fprintf(stderr, "DEBUG add sig import\n");
      status = ob_crypto_verify_signature(ob_ctx, &ec_public_key, message, message_length,
        &signature);
    };
    if (status EQUALS ST_OK)
      fprintf(ob_ctx->log, "SIGNATURE VERIFIED\n");
    break;
#endif
  };
  };

  if (status != ST_OK)
  {
    fprintf(ob_ctx->log, "test-ec: return status was %d.\n", status);
    if (status EQUALS STOB_CRYPTO_SUBSYSTEM)
    {
      OB_CRYPTO_CONTEXT_EC *internal;
      internal = ec_public_key.internal;
      fprintf(my_test_context.log, "Subsystem error %d.\n", internal->last_wolfssl_error);
    };
  };

  return(status);

} /* test-ec */


int load_public_key
  (TEST_CONTEXT *ctx,
  char *filename,
  unsigned char *buffer,
  int *buffer_length)

{ /* load_public_key */

  FILE *pkfile;
  int status;


  status = ST_OK;
  pkfile = fopen(ctx->key_filename, "r");
  if (pkfile != NULL)
    *buffer_length = fread(buffer, sizeof(unsigned char), *buffer_length, pkfile);
  else
    status = -1;
  return(status);

} /* load_public_key */


int initialize_test
  (TEST_CONTEXT *ctx,
  int argc,
  char *argv [])

{ /* initialize_test */

  int done;
  int i;
  int longindex;
  int status;
  int status_opt;


  status = ST_OK;
  ctx->log = stderr;
  ctx->curve = OB_CRYPTO_CURVE_SECP256R1;
  ctx->verbosity = 3;
  ctx->command = CMD_TEST_IMPORT_AND_VERIFY;
  strcpy(ctx->key_filename, "ec_pubkey.der");
  strcpy(ctx->message_filename, "message.bin");
  strcpy(ctx->signature_filename, "signature.bin");
  done = 0;

  // read switches
  while (!done)
  {
    status_opt = getopt_long (argc, argv, optstring, longopts, &longindex);
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "--option switch %d. processed.\n", ctx->option_switch);
    switch (ctx->option_switch)
    {
    case OPT_NOOP:
      // stay silent if looping around after an option was found.
      break;

    case OPT_CURVE:
      if (!strcmp(optarg, "secp256r1"))
        ctx->curve = OB_CRYPTO_CURVE_SECP256R1;
      if (!strcmp(optarg, "brainpoolP256r1"))
        ctx->curve = OB_CRYPTO_CURVE_BRAINPOOLP256R1;
      if (ctx->verbosity > 3)
        fprintf(ctx->log, "-- curve is %d.\n", ctx->curve);
      break;

    case OPT_COMMAND:
      sscanf(optarg, "%d", &i);
      ctx->command = i;
      break;

    case OPT_KEY:
      strcpy(ctx->key_filename, optarg);
      break;

    case OPT_MESSAGE:
      strcpy(ctx->message_filename, optarg);
      break;

    case OPT_READER:
      sscanf(optarg, "%d", &i);
      ctx->reader_index = i;
      break;

    case OPT_SETTINGS:
      strcpy(ctx->settings_filename, optarg);
      break;

    case OPT_SIGNATURE:
      strcpy(ctx->signature_filename, optarg);
      break;

    case OPT_VERBOSITY:
      sscanf(optarg, "%d", &i);
      ctx->verbosity = i;
      break;

    case OPT_HELP:
      fprintf(ctx->log, "--help - display this help text.\n");
      fprintf(ctx->log, "--command <0-4> - command to execute.  1=load/verify\n");
      fprintf(ctx->log, "--curve <curve name> - secp256r1 or brainpoolP256r1\n");
      fprintf(ctx->log, "--key <key filename> - DER encoded public key\n");
      fprintf(ctx->log, "--message <message filename> - binary file to be signed.\n");
      fprintf(ctx->log, "--reader <reader index> - which reader, (0 or 1)\n");
      fprintf(ctx->log, "--verbosity (min 1 max 9)\n");
      status = -3;
      break;
    };
    ctx->option_switch = OPT_NOOP; // reset from whatever getopt_long set it to
    if ((status_opt EQUALS -1) || (status != ST_OK))
      done = 1;
  };
  return(status);

} /* initialize_test */

