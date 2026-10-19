/*
  obtest-getcert - get a certificate from an 800-73 card.

  Usage:
    obtest-getcert

  Assumes openbadger-settings.json is present and configures
  verbosity and reader.

  It saves the cert in obtest-retrieved-cert.der

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
#include <string.h>
#include <stdlib.h>


#include <jansson.h>
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-crypto.h>
#include <ob-7816.h>
#include <openbadger-version.h>
#include <ob-pcsc.h>
#include <ob-73-4.h>
unsigned char ob_test_piv [] = OB_PIV_APPLICATION_IDENTIFIER;
BYTE command_getdata_card_auth_cert [] = { 0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x01, 0x00 };
BYTE command_get_results [] = { 0x00, 0xC0, 0x00, 0x00, 0x00 };
#define OBTEST_GETCERT_RESULTS ("obtest-retrieved-cert.der")


int obtest_init_settings
  (OB_CONTEXT *ctx)

{ /* obtest_init_settings */

  int status;


  status = ST_OK;
  ctx->verbosity = 3;
  ctx->log = stderr;
  status = ob_read_settings(ctx);
  if (status EQUALS ST_OK)
  {
    ctx->der_out = fopen(OBTEST_GETCERT_RESULTS, "w");
    if (NULL EQUALS ctx->der_out)
      status = STOB_INIT_FILES;
  };

  return(status);

} /* obtest_init_settings */


int main
  (int argc,
  char *argv [])

{ /* main for obtest-getcert */

  OB_CONTEXT *ctx;
  DWORD dwRecvLength;
  int extracted_cert_length;
  int more;
  int offset;
  BYTE pbRecvBuffer [2*OB_7816_APDU_PAYLOAD_MAX]; // probably actually 1x plus 2
  OB_RDRCTX pcsc_reader_context;
  unsigned char raw_certificate [32768];
  int raw_cert_offset;
  int raw_cert_length;
  int rdr;
  OB_RDRCTX *rdrctx;
  unsigned char smartcard_select_command [OB_7816_BUFFER_MAX];
  int smartcard_select_command_length;
  int status;
  int status_compress;
  LONG status_pcsc;
  int status_io;
  unsigned char status_7816_sw1;
  unsigned char status_7816_sw2;
  OB_CONTEXT test_piv_context;
  unsigned char uncompressed_certificate [32768];
  size_t uncomp_lth;


  ctx = &test_piv_context;
  memset(ctx, 0, sizeof(*ctx));
  ctx->rdrctx = &pcsc_reader_context;
  rdrctx = ctx->rdrctx;
  smartcard_select_command_length = 0;
  ctx->apdu_payload_max_7816 = OB_7816_APDU_PAYLOAD_MAX;
  status = obtest_init_settings(ctx);
  if (argc > 1)
  {
    rdr = *(0+(argv[1]));
    ctx->reader_index = rdr - 0x30;
    fprintf(stderr, "Reader %d.\n", ctx->reader_index);
  };
  fprintf(stderr, "obtest-challenge %s\n", OPENBADGER_VERSION);

  if (status EQUALS ST_OK)
  {
    status = ob_init_smartcard(ctx);
  };

  if (status EQUALS ST_OK)
  {

  // send application select to card

  memcpy(smartcard_select_command, ob_test_piv, sizeof(ob_test_piv));
  smartcard_select_command_length = sizeof(ob_test_piv);
  if (ctx->verbosity > 9)
  {
    ob_dump_buffer (ctx, smartcard_select_command, smartcard_select_command_length, 0);
  };
  dwRecvLength = sizeof(pbRecvBuffer);
  status_pcsc = SCardTransmit(rdrctx->pcsc, &rdrctx->pioSendPci, smartcard_select_command, smartcard_select_command_length, NULL, pbRecvBuffer, &dwRecvLength);
  rdrctx->last_pcsc_status = status_pcsc;
  if (SCARD_S_SUCCESS != status_pcsc)
    status = STOB_PCSC_TRANSMIT_1;
  };
  if (status != ST_OK)
  {
    fprintf(stderr, "Select returns: ");
    ob_dump_buffer (ctx, pbRecvBuffer, dwRecvLength, 0);
  }
  else
  {
    fprintf(stderr, "Select succeeded.\n");
  };

  if (status EQUALS ST_OK)
  {
    // ask for the card auth cert

    dwRecvLength = sizeof(pbRecvBuffer);
    if (ctx->verbosity > 3)
      ob_dump_buffer(ctx, command_getdata_card_auth_cert, sizeof (command_getdata_card_auth_cert), 0);
    status_pcsc = SCardTransmit(rdrctx->pcsc, &rdrctx->pioSendPci, command_getdata_card_auth_cert, sizeof(command_getdata_card_auth_cert), NULL, pbRecvBuffer, &dwRecvLength);
    if (SCARD_S_SUCCESS != status_pcsc)
      status = STOB_PIV_GETCERT;
    if (ctx->verbosity > 3)
    {
      fprintf(stderr, "First getcert response ");
      ob_dump_buffer (ctx, pbRecvBuffer, dwRecvLength, 0);
    };
  };
  if (status EQUALS ST_OK)
  {
    raw_cert_length = 0;

    // buffer first (or only) chunk of response

    memcpy(raw_certificate + raw_cert_length, pbRecvBuffer, dwRecvLength-2);
    raw_cert_length = raw_cert_length + dwRecvLength - 2;

    // if there's more, loop

    more = 0;
    status_7816_sw1 = pbRecvBuffer [dwRecvLength-2];
    status_7816_sw2 = pbRecvBuffer [dwRecvLength-1];
    if (status_7816_sw1 EQUALS 0x61)
    {
      more = 1;
      fprintf(stderr, "almost done, next will contain %d. octets.\n", status_7816_sw2);
    };
    if (more)
    {
      fprintf(stderr, "Retrieving next part of certificate.\n");
    };
    while (more)
    {
      dwRecvLength = sizeof (pbRecvBuffer);
      status_pcsc = SCardTransmit(rdrctx->pcsc, &rdrctx->pioSendPci, command_get_results, sizeof(command_get_results), NULL, pbRecvBuffer, &dwRecvLength);
      if (SCARD_S_SUCCESS != status_pcsc)
        status = STOB_GETCERT_FRAGMENT;
      if (ctx->verbosity > 3)
      {
        fprintf(stderr, "Last 2: %02x %02x\n", pbRecvBuffer [dwRecvLength-2], pbRecvBuffer [dwRecvLength-1]);
      };
      if (status EQUALS ST_OK)
      {
        memcpy(raw_certificate + raw_cert_length, pbRecvBuffer, dwRecvLength-2);
        raw_cert_length = raw_cert_length + dwRecvLength - 2;

        fprintf(stderr, "Next getcert response ");
        ob_dump_buffer (ctx, pbRecvBuffer, dwRecvLength, 0);
        if (0x61 != pbRecvBuffer [dwRecvLength-2])
          more = 0;
      };
      if (status != ST_OK)
        more = 0;
    };
  };
  if (status EQUALS ST_OK)
  {
      // magic value for compressed certificate is 1F 8B
      offset = 0;
      offset = offset + 4; //tag level 2 0x70
      offset = offset + 2; // L2 length
      extracted_cert_length = raw_certificate [offset] * 256 + raw_certificate [offset+1];
      raw_cert_offset = offset+2; // skip length after tag 70

      // if it's got the compression tag decompress it
    
      if ((raw_certificate [raw_cert_offset] EQUALS 0x1F) && 
         (raw_certificate [raw_cert_offset+1] EQUALS 0x8B))
      {
        uncomp_lth = sizeof(uncompressed_certificate);
        status_compress = ob_decompress_gzip(uncompressed_certificate, &uncomp_lth, raw_certificate+raw_cert_offset, extracted_cert_length);
        if (ctx->verbosity > 3)
          fprintf(stderr, "decompression status %d. in length %d. out length %lu.\n",
            status_compress, extracted_cert_length, uncomp_lth);
      }
      else
      {
        fprintf(stderr, "not compressed, using as-is.\n");

        memcpy(uncompressed_certificate, raw_certificate+raw_cert_offset, extracted_cert_length);
        uncomp_lth = extracted_cert_length;
      };
  };
  if (status EQUALS ST_OK)
  {
    status_io = fwrite(uncompressed_certificate, sizeof(uncompressed_certificate [0]), uncomp_lth, ctx->der_out);
    if (ctx->verbosity > 3)
      fprintf(stderr, "Wrote %d. bytes to der cert\n", status_io);
  };

  if (status != ST_OK)
  {
    fprintf(stderr, "obtest-getcert completed with status %d. (PCSC status %lX)\n", status, rdrctx->last_pcsc_status);
  };
  return(status);

} /* main for obtest-getcert */

