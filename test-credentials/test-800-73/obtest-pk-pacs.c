
#if 0

get the cert with obtest-getcert
set reader in openbadger-settings.json

output file is not der it's compressed, see magic number at front, not DER (dumpasn1 won't handle it.)

for pk-pacs

get cert
see lib for that for cyclone
pull public key
create challenge
send challenge
check response
then use extension in cert


#endif

/*
  obtest-getcert - get a certificate from an 800-73 card.

  Usage:
    obtest-getcert <readernumber>

  readernumber is which reader to use.

  It saves the cert in obtest-retrieved-cert.der

  Uses ./obtest-settings.json and /opt/tester/etc/obtest-settings.json

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

#ifdef USE_MBEDTLS
#include "mbedtls/x509_crt.h"
#endif
#ifdef USE_WOLFSSL
// include wolfSSL wolfCrypto
#define WOLFSSL_USE_OPTIONS_H
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

#include <openbadger-common.h>
#include <ob-crypto.h>
#include <ob-7816.h>
#include <ob-object-identifiers.h>
#include <openbadger-version.h>
#include <ob-pcsc.h>
#include <ob-73-4.h>
unsigned char ob_test_piv [] = OB_PIV_APPLICATION_IDENTIFIER;
BYTE command_getdata_card_auth_cert [] = { 0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x01, 0x00 };
BYTE command_get_results [] = { 0x00, 0xC0, 0x00, 0x00, 0x00 };
#define OBTEST_GETCERT_RESULTS ("obtest-retrieved-cert.der")


int oid_match(unsigned short int *oid1, unsigned short int *oid2, int length)
{
  int j;
  int retval;

//fprintf(stderr, "DEBUG: oid_match lth %d.\n", length);
  retval = 0;
  for (j=0; j<length; j++)
  {
//fprintf(stderr, "DEBUG: oid_match 1 %x 2 %x\n", oid1[j], oid2[j]);
    if (oid1 [j] != oid2 [j])
      retval = -1;
  };
  return(retval);
}
int my_callback
(const word16* oid, word32 oidSz, int crit,
                         const unsigned char* der, word32 derSz)
{
  int found;
  int i;

if (0)
{
  int q;
  fprintf(stderr, "DEBUG: oid and taglio uid1\n");
  for (q=0; q<oidSz; q++)
    fprintf(stderr, " %02x", oid [q]);
  fprintf(stderr, "\n");
  for (q=0; q<oidSz; q++)
    fprintf(stderr, " %02x", int_oid_taglio_pkpacs_uid1 [q]);
  fprintf(stderr, "\n");
}

  found = 0;
  if (!oid_match((unsigned short int *)oid, int_oid_pkpacs_uid1, oidSz))
  {
    fprintf(stderr, "PK-PACS UID1 (.2)\n");
    found = 1;
  };
  if (!oid_match((unsigned short int *)oid, int_oid_taglio_pkpacs_csn, oidSz))
  {
    fprintf(stderr, "Taglio PK-PACS CSN (44986.8.8)\n");
    found = 1;
  };
  if (!oid_match((unsigned short int *)oid, int_oid_taglio_pkpacs_uid1, oidSz))
  {
    fprintf(stderr, "Taglio PK-PACS UID1 (44986.8.2)\n");
    found = 1;
  };
  if (!oid_match((unsigned short int *)oid, int_oid_pkpacs_uid2, oidSz))
  {
    fprintf(stderr, "PK-PACS UID2 (.3)\n");
    found = 1;
  };
  if (!oid_match((unsigned short int *)oid, int_oid_pkpacs_uuid, oidSz))
  {
    fprintf(stderr, "PK-PACS UUID (.1)\n");
    found = 1;
  };
  if (!oid_match((unsigned short int *)oid, int_oid_taglio_pkpacs_uuid, oidSz))
  {
    fprintf(stderr, "Taglio PK-PACS UUID (44986.8.1)\n");
    found = 1;
  };
  if (!found)
    fprintf(stderr, "unknown extension callback was called\n");
  fprintf(stderr, "oid size %d. der size %d.\n",
    oidSz, derSz);
  fprintf(stderr, "OID(DER):");
  for (i=0; i<oidSz; i++)
    fprintf(stderr, " %02X", oid[i]);
  fprintf(stderr, " Value(DER):");
  for (i=0; i<derSz; i++)
    fprintf(stderr, " %02X", der[i]);
  fprintf(stderr, "\n");
  return(0);
}


int obtest_init_settings
  (OB_CONTEXT *ctx)

{ /* obtest_init_settings */

  int status;


  status = ST_OK;

  // read ./obtest-settings.json if it's there

  // read /opt/tester/etc/obtest-settings.json as an alt source

  ctx->verbosity = 9;
  ctx->der_out = fopen(OBTEST_GETCERT_RESULTS, "w");
  if (NULL EQUALS ctx->der_out)
    status = STOB_INIT_FILES;
  if (status EQUALS ST_OK)
    status = ob_read_settings(ctx);

  return(status);

} /* obtest_init_settings */


int main
  (int argc,
  char *argv [])

{ /* main for obtest-getcert */

  OB_CONTEXT *ctx;
  DWORD dwRecvLength;
  int more;
  BYTE pbRecvBuffer [2*OB_7816_APDU_PAYLOAD_MAX]; // probably actually 1x plus 2
  OB_RDRCTX pcsc_reader_context;
  int rdr;
  OB_RDRCTX *rdrctx;
  unsigned char smartcard_select_command [OB_7816_BUFFER_MAX];
  int smartcard_select_command_length;
  int status;
  LONG status_pcsc;
  unsigned char status_7816_sw1;
  unsigned char status_7816_sw2;
  OB_CONTEXT test_piv_context;
  unsigned char uncompressed_certificate [16304];
  size_t uncomp_lth;
  unsigned char whole_certificate [16384];
  int whole_idx;


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
    // buffer first (or only) chunk of response

    fwrite(pbRecvBuffer, sizeof(pbRecvBuffer[0]), dwRecvLength-2, ctx->der_out);
    whole_idx = 0;
    memcpy(whole_certificate+whole_idx, pbRecvBuffer, dwRecvLength-2);
    whole_idx = whole_idx + (dwRecvLength-2);

    // if there's more, loop

    more = 0;
    status_7816_sw1 = pbRecvBuffer [dwRecvLength-2];
    status_7816_sw2 = pbRecvBuffer [dwRecvLength-1];
    if ((status_7816_sw1 EQUALS 0x61) && (status_7816_sw2 EQUALS 0))
      more = 1;
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
        fwrite(pbRecvBuffer, sizeof(pbRecvBuffer[0]), dwRecvLength-2, ctx->der_out);
        memcpy(whole_certificate+whole_idx, pbRecvBuffer, dwRecvLength-2);
        whole_idx = whole_idx + (dwRecvLength-2);

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
    int cert_lth;
    int cert_offset;
    FILE *f;
    int offset;
    int status_compress;
    int status_io;

// 1F 8B
offset = 0;
offset = offset + 4; //tag level 2 0x70
offset = offset + 2; // L2 length
cert_lth = whole_certificate [offset] * 256 + whole_certificate [offset+1];
    // if it's got the compression tag decompress it
    
    cert_offset = offset + 2;
    if ((whole_certificate [cert_offset] EQUALS 0x1F) && 
       (whole_certificate [cert_offset+1] EQUALS 0x8B))
    {
uncomp_lth = sizeof(uncompressed_certificate);
status_compress = ob_decompress_gzip(uncompressed_certificate, &uncomp_lth, whole_certificate+cert_offset, cert_lth);
    if (ctx->verbosity > 3)
      fprintf(stderr, "decompression status %d. in length %d. out length %lu.\n",
        status_compress, cert_lth, uncomp_lth);
    }
    else
    {
      fprintf(stderr, "not compressed, using as-is.\n");
      memcpy(uncompressed_certificate, whole_certificate+cert_offset, cert_lth);
      uncomp_lth = cert_lth;
    };

    f = fopen ("cert.der", "w");
    status_io = fwrite (uncompressed_certificate, sizeof(uncompressed_certificate[0]), uncomp_lth, f);
    fprintf (stdout, "created cert.der, %d bytes %d.\n", whole_idx, status_io);
    fclose(f);
  };
  if (status EQUALS ST_OK)
#ifdef USE_MBEDTLS
  {
    mbedtls_x509_crt cert;
    int ret;


    mbedtls_x509_crt_init(&cert);
    ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)uncompressed_certificate, uncomp_lth);
    if (ret != 0) 
      fprintf(stderr, "mbedtls_x509_crt_parse status %d.\n", ret);
  };
#endif
#ifdef USE_WOLFSSL
      {
unsigned char public_key_DER [20000]; word32 pubKeyDerSz;
        DecodedCert certificate_decoded;
        int status_wolfssl;
int ret;



        wc_InitDecodedCert(&certificate_decoded, uncompressed_certificate, uncomp_lth, 0);
ret = wc_SetUnknownExtCallback(&certificate_decoded, my_callback);
fprintf(stderr, "callback set status %d.\n", ret);
        status_wolfssl = wc_ParseCert(&certificate_decoded, CERT_TYPE, NO_VERIFY, NULL);
        fprintf(stderr, "DEBUG: wc_ParseCert status %d. %X\n", status_wolfssl, status_wolfssl);
        status_wolfssl = wc_GetSubjectPubKeyInfoDerFromCert(uncompressed_certificate, uncomp_lth, public_key_DER, &pubKeyDerSz);
        fprintf(stderr, "DEBUG: wolfssl status %d. %X\n", status_wolfssl, status_wolfssl);
      };
#endif
  return(status);

} /* main for obtest-getcert */

