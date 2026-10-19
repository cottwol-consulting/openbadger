/*
  ob-pcsc - PC/SC items for openbadger

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

// official (?} PS/SC Working Group Pseudo-APDU's
// these are CLA INS P1 P2 Le

#define PAPDU_GET_ATR       {0xFA, 0x00, 0x00, 0x00, 0x00, 0x00};
#define PAPDU_GET_UID       {0xFF, 0xCA, 0x00, 0x00, 0x00};
#define PAPDU_GET_PICC_DATA {0xFF, 0xCA, 0x00, 0x02, 0x00}

// PC/SC specific reader context
typedef struct ob_rdrctx
{
  SCARDCONTEXT hContext;
  DWORD last_pcsc_status;
  SCARDHANDLE pcsc;
  SCARD_IO_REQUEST pioSendPci;
  int reader_index;
  char reader_name [OB_STRING_MAX];
} OB_RDRCTX;

int ob_init_context(OB_CONTEXT *ctx, int verbosity, FILE *log, OB_RDRCTX *rdrctx);
int ob_init_smartcard(OB_CONTEXT *ctx);
char *ob_pcsc_error_string(DWORD status_pcsc);
