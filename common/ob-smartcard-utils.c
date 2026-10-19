/*
  ob-smartcard-utils

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


#include <ob-7816.h>
#include <openbadger-common.h>
#include <openbadger-version.h>
#include <ob-pcsc.h>
#include <ob-73-4.h>


/*
  ob_init_smartcard - initialize smartcard operations.

  assumes ctx->reader_index is the reader we want.  default is zero.
  uses ctx->verbosity to control logging
*/

int ob_init_smartcard
  (OB_CONTEXT *ctx)

{ /* ob_init_smartcard */

  int done;
  DWORD dwActiveProtocol;
  LPTSTR mszReaders;
  OB_RDRCTX *rdrctx;
  DWORD reader_names_list_size;
  int offset;
  char *protocol_name;
  char *rdr_list;
  int reader_index;
  int status;
  LONG status_pcsc;


  status = ST_OK;
  rdrctx = ctx->rdrctx;

  // initialize PCSC

  status_pcsc = SCardEstablishContext (SCARD_SCOPE_SYSTEM, NULL, NULL, &(rdrctx->hContext));
  if (ctx->verbosity > 9)
  {
    fprintf(ctx->log, "DEBUG: SCardEstablishContext return value was %lX\n", status_pcsc);
  };
  if (status_pcsc != SCARD_S_SUCCESS)
    status = STOB_SCARD_ESTABLISH;

  if (status EQUALS ST_OK)
  {
  // find out how many readers are attached

  status_pcsc = SCardListReaders (rdrctx->hContext, NULL, NULL, &reader_names_list_size);
  if (ctx->verbosity > 9)
  {
    fprintf(ctx->log, "DEBUG: SCardListReaders return value was %lX\n", status_pcsc);
  };

  // enumerate to the log all reader names, until we find the one we want

  mszReaders = calloc(reader_names_list_size, sizeof(char));
  status_pcsc = SCardListReaders (rdrctx->hContext, NULL, mszReaders, &reader_names_list_size);
  if (status_pcsc != SCARD_S_SUCCESS)
    status = STOB_SCARD_ERROR;
  };
  if (status EQUALS ST_OK)
  {
    done = 0;
    offset = 0;
    reader_index = 0;
    rdr_list = mszReaders;
    ctx->reader_name [0] = 0;
    while (!done)
    {
      if (ctx->verbosity > 9)
        fprintf(ctx->log, "  Reader %d: %s\n", reader_index, rdr_list);
      if (reader_index EQUALS ctx->reader_index)
      {
        strcpy (ctx->reader_name, rdr_list);
        done = 1;
      };
      if ((1+offset) >= reader_names_list_size)
        done = 1;
      reader_index ++;
      offset = offset + strlen(rdr_list) + 1;
      rdr_list = strlen(rdr_list) + 1 + mszReaders;
    };

    if (ctx->verbosity > 9)
      if (strlen(ctx->reader_name) > 0)
        fprintf (ctx->log, "Selected reader (%d) is %s\n", ctx->reader_index, ctx->reader_name);
  };

  // initialize PCSC connection to the desired reader.

  if (status EQUALS ST_OK)
  {
    status_pcsc = SCardConnect (rdrctx->hContext, ctx->reader_name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &(rdrctx->pcsc), &dwActiveProtocol);
    if (SCARD_S_SUCCESS != status_pcsc)
      status = STOB_SCARD_CONNECT;
  };
  if (status EQUALS ST_OK)
  {
    // record if it's T0 or T1

    switch (dwActiveProtocol)
    {
    case SCARD_PROTOCOL_T0:
      rdrctx->pioSendPci = *SCARD_PCI_T0;
      protocol_name = "T0";
      break;

    case SCARD_PROTOCOL_T1:
      rdrctx->pioSendPci = *SCARD_PCI_T1;
      protocol_name = "T1";
      break;
    }
    if (ctx->verbosity > 9)
      fprintf (ctx->log, "Protocol is %s\n", protocol_name);
  };
  rdrctx->last_pcsc_status = status_pcsc;
  return(status);

} /* ob_init_smartcard */


char *ob_pcsc_error_string
  (DWORD status_pcsc)

{
  char *return_value;


  return_value = NULL;
  switch(status_pcsc)
  {
  default:
    return_value = "Unknown";
    break;
  case SCARD_E_INSUFFICIENT_BUFFER:
    return_value = "SCARD_E_INSUFFICIENT_BUFFER";
    break;
  case SCARD_E_INVALID_HANDLE:
    return_value = "SCARD_E_INVALID_HANDLE";
    break;
  case SCARD_E_NO_SERVICE:
    return_value = "SCARD_E_NO_SERVICE";
    break;
  case SCARD_E_NOT_TRANSACTED:
    return_value = "SCARD_E_NOT_TRANSACTED";
    break;
  case SCARD_W_REMOVED_CARD:
    return_value = "SCARD_W_REMOVED_CARD";
    break;
  };
  return(return_value);
}


int ob_smartcard_command_response
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
    status = STOB_CRYPTO_SMARTCARD_1;
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
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "Send:\n");
      ob_dump_buffer(ctx, command_buffer, idx, 0);
    };
    status_pcsc = SCardTransmit(rdrctx->pcsc, &(rdrctx->pioSendPci),
      command_buffer, idx, NULL, output, out_length);
    rdrctx->last_pcsc_status = status_pcsc;
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "Recv: ");
      ob_dump_buffer(ctx, output, *out_length, 0);
    };
  };
  return(status);

} /* ob_smartcard_command_response */


int ob_smartcard_command_response_raw
  (OB_CONTEXT *ctx,
  unsigned char *input,
  int in_length,
  unsigned char *output,
  DWORD *out_length)

{ /* cvc_smartcard_command_response_raw */

  OB_RDRCTX *rdrctx;
  int status;
  DWORD status_pcsc;


  status = ST_OK;
  if (in_length >256)
    status = STOB_CRYPTO_SMARTCARD_2;
  if (status EQUALS ST_OK)
  {
    rdrctx = ctx->rdrctx;
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "Send:\n");
      ob_dump_buffer(ctx, input, in_length, 0);
    };
    status_pcsc = SCardTransmit(rdrctx->pcsc, &(rdrctx->pioSendPci),
      input, in_length, NULL, output, out_length);
    rdrctx->last_pcsc_status = status_pcsc;
    fprintf(ctx->log, "Recv: ");
    ob_dump_buffer(ctx, output, *out_length, 0);
  };
  return(status);

} /* ob_smartcard_command_response_raw */

