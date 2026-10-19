/*
  ob-piv-utils - utility functions for piv-related items

  (C)Copyright 2023-2026 Smithee Solutions LLC

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
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


//#include <eac-encode.h>

#include <ob-7816.h>
#include <openbadger-common.h>
#include <openbadger-version.h>
#include <ob-pcsc.h>
#include <ob-73-4.h>
unsigned char ec_public_key_der_skeleton [] =
{
  0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00
  // actual 65 byte key goes after this
};


int ob_convert_ec_pubkey_DER
  (OB_CONTEXT *ctx,
  unsigned char *key_buffer,
  int kblth,
  unsigned char *marshalled_DER,
  int *marshalled_length)

{ /* ob_convert_ec_pubkey_DER */

  FILE *ec_der_key;


  ec_der_key = fopen("ec_public-key.der", "w");
  fwrite(ec_public_key_der_skeleton, 1, sizeof(ec_public_key_der_skeleton), ec_der_key);
  memcpy(marshalled_DER, ec_public_key_der_skeleton, sizeof(ec_public_key_der_skeleton));
  fwrite(key_buffer, 1, kblth, ec_der_key);
  memcpy(marshalled_DER+sizeof(ec_public_key_der_skeleton), key_buffer, kblth);
  fclose(ec_der_key);
  *marshalled_length = sizeof(ec_public_key_der_skeleton) + kblth;

  return(ST_OK);

} /* ob_convert_ec_pubkey_DER */


int ob_smartcard_command_responseZZZ
  (OB_CONTEXT *ctx,
  unsigned char *input,
  int in_length,
  unsigned char *output,
  DWORD *out_length,
  unsigned char CLA,
  unsigned char INS,
  unsigned char P1,
  unsigned char P2,
  unsigned char *Le,
  int Le_length)

{ /* cvc_smartcard_command_response */

  unsigned char command_buffer [257]; // TODO set to constant
  int idx;
  OB_RDRCTX *rdrctx;
  int status;
  DWORD status_pcsc;


  status = ST_OK;
  if (in_length >256)
    status = -1;
  if (status EQUALS ST_OK)
  {
    memset(command_buffer, 0, sizeof(command_buffer));
    rdrctx = ctx->rdrctx;
    idx = 0;
    command_buffer [idx] = CLA; idx++;
    command_buffer [idx] = INS; idx++;
    command_buffer [idx] = P1; idx++;
    command_buffer [idx] = P2; idx++;
    command_buffer [idx] = in_length; idx++;
    if (in_length > 0)
    {
      memcpy(command_buffer+idx, input, in_length);
      idx = idx + in_length;
    };

    if (Le_length > 0)
    {
      memcpy(command_buffer+idx, Le, Le_length);
      idx = idx + Le_length;
    };
    fprintf(ctx->log, "Send: ");
    ob_dump_buffer(ctx, command_buffer, idx, 0);
    status_pcsc = SCardTransmit(rdrctx->pcsc, &(rdrctx->pioSendPci),
      command_buffer, idx, NULL, output, out_length);
    rdrctx->last_pcsc_status = status_pcsc;
    fprintf(ctx->log, "Recv: ");
    ob_dump_buffer(ctx, output, *out_length, 0);
  };
  return(status);

} /* ob_smartcard_command_response */

