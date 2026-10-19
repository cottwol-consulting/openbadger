/*
ob-reader
  --verbosity
  --reader
  --settings
  --mechanism
  --osdp
  --signer
  --format

ob-reader switches

default is --reader 1 --mechanism pkoc --format "{bits:64}"
--verbosity 3 --settings openbadger-reader.json --osdp --signer signer-1.der

--format
format to deliver to PD.  json string or @json file

--mechanism
how to talk to card/credential.  "pkoc" or "leaf-v" or "pk-pacs-pkoc" or 
"pk-pacs-x.509" or "vde" or "pk-pacs-cvc-tsa".

--osdp
json string or @json file

--reader
index of reader in PCSC.  First reaer is zero.

--settings
settngs filename

--signer
file name of der-encoded signer appropriate for the mechanism

--verbosity
debug verbosity.  0 1 3 8 9

it then calls the transponder, which returns a json string (it calls it through the shell)

call process is:
  fill in settings from switches
  call /opt/tester/bin/ob_transponder_<MECHANISM>, use the string that comes back as the response.

response sample
  {"mechanism":"LEAF-V","card-raw":"1234","card-bits":"40","status":"0"}
*/


#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>


#define EQUALS ==
#define ST_OK (0)
#define ST_HELP (1)

typedef struct ob_reader_context
{
  int verbosity;
  FILE *log;
  int option_switch;
  int reader_index;
  char settings_filename [1024];
  char signer_filename [1024];
  char osdp_path [1024];
  char output_format [1024];
  char mechanism [1024];
} OB_READER_CONTEXT;


OB_READER_CONTEXT my_context;
#define OPT_MISSING   (-1) // guaranteed not to be there
#define OPT_NOOP      (0)
#define OPT_VERBOSITY (1)
#define OPT_HELP      (2)
#define OPT_READER    (3)
#define OPT_SETTINGS  (4)
#define OPT_SIGNER    (5)
#define OPT_OSDP_PATH (6)
#define OPT_FORMAT    (7)
#define OPT_MECHANISM (8)
char optstring [32768];

struct option longopts [] = {
  {"help", 0, &(my_context.option_switch), OPT_HELP},
  {"format", required_argument, &(my_context.option_switch), OPT_FORMAT},
  {"mechanism", required_argument, &(my_context.option_switch), OPT_MECHANISM},
  {"osdp", optional_argument, &(my_context.option_switch), OPT_OSDP_PATH},
  {"reader", required_argument, &(my_context.option_switch), OPT_READER},
  {"settings", required_argument, &(my_context.option_switch), OPT_SETTINGS},
  {"signer", required_argument, &(my_context.option_switch), OPT_SIGNER},
  {"verbosity", required_argument, &(my_context.option_switch), OPT_VERBOSITY},
  {0, 0, 0, 0}
};
int call_transponder(OB_READER_CONTEXT *ctx);


int initialize
  (OB_READER_CONTEXT *ctx,
  int argc,
  char *argv [])

{ /* initialize */

  int done;
  int i;
  int longindex;
  int status;
  int status_opt;


  status = ST_OK;
  memset(ctx, 0, sizeof(*ctx));
  ctx->log = stderr;
  ctx->verbosity = 3;
  ctx->log = stderr;
  strcpy(ctx->settings_filename, "openbadger-reader-settings.json");
  strcpy(ctx->osdp_path, "/opt/osdp-conformance/run/PD");
  ctx->reader_index = 1;
  strcpy(ctx->signer_filename, "signer-1.der");
  strcpy(ctx->output_format, "64");
  strcpy(ctx->mechanism, "pkoc");
  done = 0;

  // read switches
  ctx->option_switch = OPT_MISSING;
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

    case OPT_FORMAT:
      strcpy(ctx->output_format, optarg);
      break;

    case OPT_MECHANISM:
      strcpy(ctx->mechanism, optarg);
      break;

    case OPT_READER:
      sscanf(optarg, "%d", &i);
      ctx->reader_index = i;
      break;

    case OPT_SETTINGS:
      strcpy(ctx->settings_filename, optarg);
      break;

    case OPT_SIGNER:
      strcpy(ctx->signer_filename, optarg);
      break;

    case OPT_VERBOSITY:
      sscanf(optarg, "%d", &i);
      ctx->verbosity = i;
      break;

    default:
    case OPT_HELP:
      fprintf(ctx->log, "--help - display this help text.\n");
      fprintf(ctx->log, "--reader <reader index> - which reader, (0 or 1)\n");
      fprintf(ctx->log, "--mechanism <transponder> - which transponder to use\n");
      fprintf(ctx->log, "--settings <settings filename>\n");
      fprintf(ctx->log, "--verbosity (min 0 max 9)\n");
//  --osdp --signer --format

      status = ST_HELP;
      break;
    };
    ctx->option_switch = OPT_NOOP; // reset from whatever getopt_long set it to
    if ((status_opt EQUALS -1) || (status != ST_OK))
      done = 1;
  };
  if (status EQUALS ST_OK)
  {
  if (ctx->verbosity > 0)
  {
    fprintf(ctx->log, "          Reader: %d\n", ctx->reader_index);
    fprintf(ctx->log, "       Mechanism: %s\n", ctx->mechanism);
    fprintf(ctx->log, "          Signer: %s\n", ctx->signer_filename);
    fprintf(ctx->log, "OSDP Daemon Path: %s\n", ctx->osdp_path);
    fprintf(ctx->log, "PD output format: %s\n", ctx->output_format);
  };
  };
  return(status);

} /* initialize */


int main
  (int argc,
  char *argv [])

{ /* main for ob-reader */

  OB_READER_CONTEXT *ctx;
  int status;


  ctx = &my_context;
  status = initialize(ctx, argc, argv);
  if (status EQUALS ST_OK)
  {
    status = call_transponder(ctx);
  };
  if (status EQUALS ST_OK)
  {
fprintf(stderr, "DEBUG: consume transponder output.\n");
  };

  if (status != ST_OK)
  {
    fprintf(ctx->log, "ob-reader exit status %d.\n", status);
  };

} /* main for ob-reader */


int call_transponder
  (OB_READER_CONTEXT *ctx)

{
  char command [1024];
  FILE *tinf;
  char transponder_response [1024];
  int status_io;


fprintf(stderr, "DEBUG: set up for transponder json settings etc.\n");
  sprintf(command, "/opt/tester/bin/ob-transponder-%s >/tmp/transponder.out", ctx->mechanism);
  system(command);
  tinf = fopen("/tmp/transponder.out", "r");
  status_io = fread(transponder_response, 1, 1024, tinf);
  fclose(tinf);
  fprintf(stderr, "transponder returned(%d) %s\n", status_io, transponder_response);
  return(ST_OK);
}

