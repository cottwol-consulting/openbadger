/*
  obtest-util - openbadger smartcard management utilities

  Usage:
    obtest-util 

  Assumes openbadger-settings.json in current directory.

  Reader number is default 0.  Note Contact/Contactless readers might
  have the CL interface on reader 1.  Use "opensc-tool --list-readers" to check.
  Set verbosity to 9 for verbose logging.

  (C)Copyright 2026 Cottwol Consulting

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
#include <ob-7816.h>
#include <ob-pcsc.h>
#include <openbadger-version.h>
#define RESPONSE_LENGTH(r) r ## _length
#define TRY_SMARTCARD(tag,report_label,command_apdu,response_actual) \
{ \
  strcpy(test_tag, tag); \
  pcsc_receive_length = sizeof(pcsc_receive_buffer); \
  status = try_smartcard(ctx, test_tag, command_apdu, sizeof(command_apdu), pcsc_receive_buffer, &pcsc_receive_length); \
  if (status EQUALS ST_OK) \
  { \
    if ( ((ctx->last_7816_status [0] EQUALS 0x90) && (ctx->last_7816_status [1] EQUALS 0x00))) \
    { \
      if (pcsc_receive_length > 2) \
      { \
        response_length = pcsc_receive_length - 2; \
        fprintf(ctx->log, report_label); \
        ob_dump_buffer(ctx, pcsc_receive_buffer, response_length, 0); \
        memcpy(response_actual, pcsc_receive_buffer, response_length); \
        RESPONSE_LENGTH(response_actual) = response_length; \
      }; \
    }; \
  }; \
  fprintf(ctx->log, "---Test %s completed.\n", test_tag); \
};


unsigned char an10957_select [] =
{0x00, 0xA4, 0x04, 0x00, 0x09, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0xF5, 0x32, 0xF0, 0x00 };
unsigned char leaf_universal_select [] =
{0x00, 0xA4, 0x04, 0x00, 0x09, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0xF5, 0x1C, 0xD8, 0x00 };
unsigned char pkoc_select [] = 
{0x00, 0xa4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x08, 0x98, 0x00, 0x00, 0x01, 0x00};
unsigned char get_ef_info [] = APDU_GET_DATA_EF_INFO;
unsigned char              desfire_challenge [] = {0x90, 0x1A, 0x00, 0x00, 0x01, 0x00};
unsigned char                        get_atr [] = PAPDU_GET_ATR;
unsigned char get_card_production_life_cycle [] = APDU_GET_CPLC;
unsigned char      get_card_recognition_data [] = APDU_GET_CARD_RECOGNITION_DATA;
unsigned char                  get_picc_data [] = PAPDU_GET_PICC_DATA;
unsigned char                        get_uid [] = PAPDU_GET_UID;
unsigned char                     select_any [] = APDU_SELECT_ANY;
int bad_status; // kludge should be in an arg to try_smartcard


int initialize(OB_CONTEXT *ctx, OB_RDRCTX *rdrctx);
int try_smartcard(OB_CONTEXT *ctx, char *test_tag, unsigned char *command_to_smartcard, int command_to_smartcard_length,
  unsigned char *returned_value, DWORD *returned_length);


int main
  (int argc,
  char *argv[])

{ /* main for obtest-util */

  OB_CONTEXT *ctx;
  unsigned char discarded_answer [1024]; // used when not set up for response
  int discarded_answer_length;
  OB_CONTEXT my_openbadger_context;
  OB_RDRCTX pcsc_reader_context;
  BYTE pcsc_receive_buffer [2*OB_7816_APDU_PAYLOAD_MAX];
  DWORD pcsc_receive_length;
  unsigned char response_an10957 [1024];
  int response_an10957_length;
  unsigned char response_atr [1024]; // lth max?
  int response_atr_length;
  unsigned char response_desfire [1024];
  int response_desfire_length;
  unsigned char response_ef_info [1024];
  int response_ef_info_length;
  unsigned char response_gp_card_recognition [1024];
  int response_gp_card_recognition_length;
  unsigned char response_gp_card_production_life_cycle [1024];
  int response_gp_card_production_life_cycle_length;
  unsigned char response_leaf_universal [1024];
  int response_leaf_universal_length;
  unsigned char response_pkoc [1024];
  int response_pkoc_length;
  int response_length;
  unsigned char response_select_any [1024];
  int response_select_any_length;
  unsigned char response_uid [10]; //uid3
  int response_uid_length;
  int status;
  char test_tag [1024];


  bad_status = 0;
  discarded_answer_length = 0;
  memset(discarded_answer, 0, sizeof(discarded_answer));
  response_an10957_length = 0;
  response_atr_length = 0;
  response_ef_info_length = 0;
  response_gp_card_recognition_length = 0;
  response_leaf_universal_length = 0;
  response_pkoc_length = 0;
  response_select_any_length = 0;
  response_uid_length = 0;
// todo why payload file as dynamic
  ctx = &my_openbadger_context;
  status = initialize(ctx, &pcsc_reader_context);
  if (status EQUALS ST_OK)
  {
    fprintf(ctx->log, "obtest-util - smartcard contents examiner %s\n", OPENBADGER_VERSION);
    if (ctx->verbosity > 3)
      fprintf(ctx->log, "--verbosity set to %d.\n", ctx->verbosity);

    ctx->rdrctx = &pcsc_reader_context;
  };

  if (status EQUALS ST_OK)
  {
    if (status EQUALS ST_OK)
    {
      strcpy(test_tag, "GET-UID");
      pcsc_receive_length = sizeof(pcsc_receive_buffer);
      status = try_smartcard(ctx, test_tag, get_uid, sizeof(get_uid), pcsc_receive_buffer, &pcsc_receive_length);
      if (status EQUALS ST_OK)
      {
        if ( ((ctx->last_7816_status [0] EQUALS 0x90) && (ctx->last_7816_status [1] EQUALS 0x00)))
        {
          if (pcsc_receive_length > 2)
          {
            response_length = pcsc_receive_length - 2;
            fprintf(ctx->log, "PCSC UID Response: ");
            ob_dump_buffer (ctx, pcsc_receive_buffer, response_length, 0);
            memcpy(response_uid, pcsc_receive_buffer, response_length);
            response_uid_length = response_length;
          };
        };
      };
      fprintf(ctx->log, "---Test %s completed.\n", test_tag);
    };
    if (status EQUALS ST_OK)
    {
      strcpy(test_tag, "GET-ATR");
      pcsc_receive_length = sizeof(pcsc_receive_buffer);
      status = try_smartcard(ctx, "GET-ATR", get_atr, sizeof(get_atr), pcsc_receive_buffer, &pcsc_receive_length);
      if (status EQUALS ST_OK)
      {
        if ( ((ctx->last_7816_status [0] EQUALS 0x90) && (ctx->last_7816_status [1] EQUALS 0x00)))
        {
          if (pcsc_receive_length > 2)
          {
            response_length = pcsc_receive_length - 2;
            fprintf(ctx->log, "PCSC ATR Response: ");
            ob_dump_buffer (ctx, pcsc_receive_buffer, response_length, 0);
            memcpy(response_atr, pcsc_receive_buffer, response_length);
            response_atr_length = response_length;
          };
        };
      };
      fprintf(ctx->log, "---Test %s completed.\n", test_tag);
    };
    if (status EQUALS ST_OK)
    {
      strcpy(test_tag, "GET-GP-CARD-RECOGNITION");
      pcsc_receive_length = sizeof(pcsc_receive_buffer);
      status = try_smartcard(ctx, test_tag, get_card_recognition_data, sizeof(get_card_recognition_data), pcsc_receive_buffer, &pcsc_receive_length);
      if (status EQUALS ST_OK)
      {
        if ( ((ctx->last_7816_status [0] EQUALS 0x90) && (ctx->last_7816_status [1] EQUALS 0x00)))
        {
          if (pcsc_receive_length > 2)
          {
            response_length = pcsc_receive_length - 2;
            fprintf(ctx->log, "GP Card Recognition Data: ");
            ob_dump_buffer (ctx, pcsc_receive_buffer, response_length, 0);

            memcpy(response_gp_card_recognition, pcsc_receive_buffer, response_length);
            response_gp_card_recognition_length = response_length;
          };
        };
      };
      fprintf(ctx->log, "---Test %s completed.\n", test_tag);
    };
    if (status EQUALS ST_OK)
    {
      strcpy(test_tag, "GET-GP-CPLC");
      pcsc_receive_length = sizeof(pcsc_receive_buffer);
      status = try_smartcard(ctx, test_tag, get_card_production_life_cycle, sizeof(get_card_production_life_cycle), pcsc_receive_buffer, &pcsc_receive_length);
      if (status EQUALS ST_OK)
      {
        if ( ((ctx->last_7816_status [0] EQUALS 0x90) && (ctx->last_7816_status [1] EQUALS 0x00)))
        {
          if (pcsc_receive_length > 2)
          {
            response_length = pcsc_receive_length - 2;
            fprintf(ctx->log, "GP Card Production Life Cycle: ");
            ob_dump_buffer (ctx, pcsc_receive_buffer, response_length, 0);

            memcpy(response_gp_card_production_life_cycle, pcsc_receive_buffer, response_length);
            response_gp_card_production_life_cycle_length = response_length;
          };
        };
      };
      fprintf(ctx->log, "---Test %s completed.\n", test_tag);
    };
    if (status EQUALS ST_OK)
    {
      strcpy(test_tag, "GET-PICC-DATA");
      pcsc_receive_length = sizeof(pcsc_receive_buffer);
      status = try_smartcard(ctx, "GET-PICC-DATA", get_picc_data, sizeof(get_picc_data), pcsc_receive_buffer, &pcsc_receive_length);
      if (status EQUALS ST_OK)
      {
        if ( ((ctx->last_7816_status [0] EQUALS 0x90) && (ctx->last_7816_status [1] EQUALS 0x00)))
        {
          if (pcsc_receive_length > 2)
          {
            response_length = pcsc_receive_length - 2;
            fprintf(ctx->log, "PCSC PICC Data: ");
            ob_dump_buffer (ctx, pcsc_receive_buffer, response_length, 0);
          };
        };
      };
      fprintf(ctx->log, "---Test %s completed.\n", test_tag);
    };
    if (status EQUALS ST_OK)
    {
      TRY_SMARTCARD("SELECT-ANY",
        "Select(GP Issure Security Domain): ", select_any, response_select_any);
    };
    if (status EQUALS ST_OK)
    {
      TRY_SMARTCARD("GET-EF-INFO",
        "7816 EF.ATR/INFO: ", get_ef_info, response_ef_info);
      fprintf(ctx->log, "%s response length is %d.\n", "GET_EF_INFO", response_ef_info_length);
    };
    if (status EQUALS ST_OK)
    {
      TRY_SMARTCARD("AN10957-SELECT",
        "NXP AN-10957 Select: ", an10957_select, response_an10957);
      fprintf(ctx->log, "%s response length is %d.\n", "AN10957-SELECT", response_an10957_length);
    };
    if (status EQUALS ST_OK)
    {
      TRY_SMARTCARD("PKOC-SELECT",
        "PKOC Select: ", pkoc_select, response_pkoc);
      fprintf(ctx->log, "%s response length is %d.\n", "PKOC-SELECT", response_pkoc_length);
    };
    if (status EQUALS ST_OK)
    {
      TRY_SMARTCARD("LEAF-UNIVERSAL-SELECT",
        "Wavelynx LEAF Universal Select: ",
        leaf_universal_select, response_leaf_universal);
      fprintf(ctx->log, "%s response length is %d.\n", "LEAF-UNIVERSAL-SELECT", response_leaf_universal_length);
    };
    if (status EQUALS ST_OK)
    {
      TRY_SMARTCARD("DESFIRE-GET-CHALLENGE",
        "DESFire Challenge: ", desfire_challenge, response_desfire);
    };
{
unsigned char response_desfire_get_version [1024];
int response_desfire_get_version_length;
response_desfire_get_version_length = 0;
unsigned char desfire_get_version [] = {0x90, 0x60, 0x00, 0x00, 0x00};
    if (status EQUALS ST_OK)
    {
      TRY_SMARTCARD("DESFIRE-GET-VERSION",
        "DESFire GetVersion: ", desfire_get_version, response_desfire_get_version);
fprintf(ctx->log, "DESfire get version response length %d\n",
  response_desfire_get_version_length);
    };
}

    if (status EQUALS ST_OK)
    {
unsigned char atr_buffer [1024]; // ?
DWORD atr_buffer_length;
char reader_name [1024];
DWORD reader_name_length;
DWORD reader_prot;
DWORD reader_state;

      strcpy(test_tag, "SCARD-STATUS");
      fprintf(ctx->log, "---Test %s started.\n", test_tag);

      atr_buffer_length = sizeof(atr_buffer);
      reader_name_length = sizeof(reader_name);

      pcsc_reader_context.last_pcsc_status = SCardStatus(pcsc_reader_context.pcsc, reader_name, &reader_name_length,
        &reader_state, &reader_prot, atr_buffer, &atr_buffer_length);
fprintf(ctx->log, "Reader state %lX\n", reader_state);
      ob_dump_buffer (ctx, atr_buffer, atr_buffer_length, 0);
      memcpy(response_atr, atr_buffer, atr_buffer_length);
      response_atr_length = atr_buffer_length;
      fprintf(ctx->log, "---Test %s completed.\n", test_tag);
    };
  };

  if (status EQUALS ST_OK)
  {
    if (bad_status > 0)
      fprintf(ctx->log, "testing completed.  %d. 7816 error responses.\n", bad_status);
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "last discarded response: \n");
      ob_dump_buffer (ctx, discarded_answer, discarded_answer_length, 0);
    };
    fprintf(stdout, "{\n");
    fprintf(stdout,
"  \"UID\":\"%s\",\n", 
      ob_buffer_dump_string_ex(&my_openbadger_context, response_uid, response_uid_length, "", 1));
    if (response_select_any_length > 0)
    {
      fprintf(stdout,
"  \"select-any-answer\":\"%s\",\n",
      ob_buffer_dump_string_ex(&my_openbadger_context, response_select_any, response_select_any_length, "", 1));
    };
    if (response_desfire_length > 0)
    {
      fprintf(stdout,
"  \"desfire-challenge-answer\":\"%s\",\n",
      ob_buffer_dump_string_ex(&my_openbadger_context, response_desfire, response_desfire_length, "", 1));
    };
    if (response_gp_card_recognition_length > 0)
    {
      fprintf(stdout,
"  \"gp-card-recognition\":\"%s\",\n",
      ob_buffer_dump_string_ex(&my_openbadger_context, response_gp_card_recognition, response_gp_card_recognition_length, "", 1));
    };
    if (response_gp_card_production_life_cycle_length > 0)
    {
      fprintf(stdout,
"  \"gp-card-production-life-cycle\":\"%s\",\n",
      ob_buffer_dump_string_ex(&my_openbadger_context, response_gp_card_production_life_cycle, response_gp_card_production_life_cycle_length, "", 1));
    };
    fprintf(stdout,
"  \"answer-to-reset\":\"%s\",\n",
      ob_buffer_dump_string_ex(&my_openbadger_context, response_atr, response_atr_length, "", 1));
    fprintf(stdout,
"  \"last-7816-error\" : \"%02X%02X\",\n", ctx->last_7816_status [0], ctx->last_7816_status [1]);
    fprintf(stdout, "  \"_end\":\"1\"\n}\n");
  };

  if (status != ST_OK)
    fprintf(ctx->log, "obtest-util exit status was %d,\n", status);


} /* main for obtest-util */


int initialize
  (OB_CONTEXT *ctx,
  OB_RDRCTX *rdrctx)

{ /* initialize */

  int status;


  status = ST_OK;
  memset(ctx, 0, sizeof(*ctx));
  ctx->verbosity = 3;
  ctx->log = stderr;
  ctx->apdu_payload_max_7816 = OB_7816_APDU_PAYLOAD_MAX;
  ctx->payload_file = malloc(1024);
  ctx->rdrctx = rdrctx;
  status = ob_read_settings(ctx);
  if (status EQUALS ST_OK)
  { 
    status = ob_init_smartcard(ctx);
  };
  return(status);

} /* initialize */


int try_smartcard
  (OB_CONTEXT *ctx,
  char *test_tag,
  unsigned char *command_to_smartcard,
  int command_to_smartcard_length,
  unsigned char *returned_value,
  DWORD *returned_length)

{ /* try_smartcard */

  OB_RDRCTX *rdrctx;
  int status;


  status = ST_OK;
  rdrctx = ctx->rdrctx;
  if (status EQUALS ST_OK)
  {
    fprintf(ctx->log, "---Test %s started.\n", test_tag);
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "Sending: ");
      ob_dump_buffer(ctx, command_to_smartcard, command_to_smartcard_length, 0);
    };
if (ctx->verbosity > 9)
{
  fprintf(stderr, "DEBUG: cmd lth %d. ret lth %d. BEFORE call\n", command_to_smartcard_length, (int)*returned_length);
};
    rdrctx->last_pcsc_status = SCardTransmit(rdrctx->pcsc, &rdrctx->pioSendPci,
      command_to_smartcard, command_to_smartcard_length, NULL, returned_value, returned_length);
if (ctx->verbosity > 3)
{
  fprintf(stderr, "DEBUG: cmd lth %d. ret lth %d. AFTER call\n", command_to_smartcard_length, (int)*returned_length);
};
    if (SCARD_S_SUCCESS != rdrctx->last_pcsc_status)
      status = STOB_PCSC_TRANSMIT_1;
  };
  if (status EQUALS ST_OK)
  {
    if ( !((*(returned_value+*returned_length-2) EQUALS 0x90) && (*(returned_value+*returned_length-1) EQUALS 0x00)) )
      bad_status++;
    memcpy(ctx->last_7816_status, returned_value+*returned_length-2, 2);
{
  char test [1024];
  strcpy(test, ob_7816_status(ctx));
  printf("7816 status %s\n", test);
    if (strlen(test) > 0)
      fprintf(ctx->log, "%s 7816 status was %s\n", test_tag, ob_7816_status(ctx));
}
//    if (strlen(ob_7816_status(ctx) > 0) fprintf(ctx->log, "%s 7816 status was %s\n", test_tag, ob_7816_status(ctx));
    if (ctx->verbosity > 3)
    {
      fprintf(ctx->log, "Test results for test %s\n", test_tag);
      ob_dump_buffer (ctx, returned_value, (int)(*returned_length), 0);
    };
  };
  if ((ctx->verbosity > 0) && (status != ST_OK))
    fprintf(ctx->log, "Return status from try_smartcard (%s) was %d.\n", test_tag, status);
  return(status);

} /* try_smartcard */

