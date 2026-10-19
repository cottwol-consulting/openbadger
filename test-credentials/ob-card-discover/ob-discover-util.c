#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include <jansson.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-7816.h>
#include <ob-pcsc.h>


/*
  ob_7816_status - verbose 7816 status description
*/

char *ob_7816_status
  (OB_CONTEXT *ctx,
  int *status_recognized)

{ /* ob_7816_status */

  int bad_interpreted;
  static char message [1024];


  *status_recognized = 0;
  message [0] = 0;
  bad_interpreted = 0;
  if ( !( (ctx->last_7816_status [0] EQUALS 0x90) && (ctx->last_7816_status [1] EQUALS 0x00)) )
    bad_interpreted = 1;
  if ( (ctx->last_7816_status [0] EQUALS 0x69) && (ctx->last_7816_status [1] EQUALS 0x82) )
  {
    sprintf(message, "%02X%02X Security status not satisfied",
      ctx->last_7816_status [0], ctx->last_7816_status [1]);
    bad_interpreted = 0;
    *status_recognized = 1;
  };
  if ( (ctx->last_7816_status [0] EQUALS 0x6A) && (ctx->last_7816_status [1] EQUALS 0x82) )
  {
    sprintf(message, "%02X%02X File not found",
      ctx->last_7816_status [0], ctx->last_7816_status [1]);
    bad_interpreted = 0;
    *status_recognized = 1;
  };
  if ( (ctx->last_7816_status [0] EQUALS 0x6A) && (ctx->last_7816_status [1] EQUALS 0x88) )
  {
    sprintf(message, "%02X%02X Reference data not found",
      ctx->last_7816_status [0], ctx->last_7816_status [1]);
    bad_interpreted = 0;
    *status_recognized = 1;
  };
  if ( (ctx->last_7816_status [0] EQUALS 0x6B) && (ctx->last_7816_status [1] EQUALS 0x00) )
  {
    sprintf(message, "%02X%02X Wrong parameters P1/P2",
      ctx->last_7816_status [0], ctx->last_7816_status [1]);
    bad_interpreted = 0;
    *status_recognized = 1;
  };
  if ( (ctx->last_7816_status [0] EQUALS 0x6E) && (ctx->last_7816_status [1] EQUALS 0x00) )
  {
    sprintf(message, "%02X%02X Class not supported",
      ctx->last_7816_status [0], ctx->last_7816_status [1]);
    bad_interpreted = 0;
    *status_recognized = 1;
  };
  if (bad_interpreted)
  {
    sprintf(message, "%02X%02X (7816 bad response)",
      ctx->last_7816_status [0], ctx->last_7816_status [1]);
    bad_interpreted = 0;
  };

  return(message);

} /* ob_7816_status */


/*
  ob-twic-support
*/

int ob_twic_support_stub (void) {return(-1);}
int ob_decode_atr
  (int *ctx,
  unsigned char atr,
  int atr_length)
{
return(-1);
}

//offset 0 TS 3B direct offset++



