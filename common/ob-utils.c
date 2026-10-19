/*
  openbadger - utility functions

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
#include <ob-crypto.h>
#include <ob-pcsc.h>
#include <ob-73-4.h>
#include <ob-pacs.h>
#include <ob-an10957.h>


void
  ob_add_tag_length
    (unsigned char *buffer,
    int length,
    int *new_buffer_length)

{ /* ob_add_tag_length */

  int upper;
  int lower;

  lower = length & 0xff;
  upper = (length & 0xff00) >> 8;
  if (length > 255)
  {
    *buffer = 0x82;
    (*new_buffer_length)++;
    *(buffer+1) = upper;
    *(buffer+2) = lower;
    (*new_buffer_length)++;
    (*new_buffer_length)++;
  }
  else
  {
    *(buffer) = lower;
    (*new_buffer_length)++;
  };
} /* ob_add_tag_length */


// assumes null-terminated input
// set max converted length

int ob_base64url_to_binary
  (OB_CONTEXT *ctx,
  char *base64_url,
  unsigned char *converted,
  int *converted_length)

{ /* ob_base64url_to_binary */

  char base64_string [1024];
  int decoded_b64_lth;
  unsigned char *p;
  char *p_in;
  char *p_out;
  int status;
  int supplied_lth;


  status = ST_OK;
  memset(base64_string, 0, sizeof(base64_string));
  supplied_lth = *converted_length;
  p_in = base64_url;
  p_out = base64_string;
  while (*p_in)
  {
    if (*p_in EQUALS '-')
      *p_out = '+';
    if (*p_in EQUALS '_')
      *p_out = '/';
    // if it wasn't set use the input
    if (!(*p_out))
      *p_out = *p_in;
    p_in++;
    supplied_lth--;
    if (supplied_lth)
      p_out++;
  };
  p = base64_decode(base64_string, &decoded_b64_lth);
  memcpy(converted, p, decoded_b64_lth);
  *converted_length = decoded_b64_lth;
  return (status);

} /* ob_base64url_to_binary */


void ob_dump_buffer
    (OB_CONTEXT *ctx,
    BYTE *bytes,
    int length,
    int dest)
{
  char no_string_output [8];
  int lth;
  lth = sizeof(no_string_output);
  return(ob_dump_buffer_ex(ctx, bytes, length, dest, &(no_string_output [0]), &lth));
}


/*
  hex dump function.

  dest is 0 for stderr 1 for stdout DUMP_INCLUDE to append to include log
  2 is for send it to the output string.
*/
void ob_dump_buffer_ex
    (OB_CONTEXT *ctx,
    BYTE *bytes,
    int length,
    int dest,
    char *out_string, 
    int *out_lth)

{ /* ob_dump_buffer_ex */

  int i;
  FILE *inclog;
  int insert_hyphen;
  int insert_space;
  int line_length;
  char log_string [8192];
  char temp_string [1024];

  memset(log_string, 0, sizeof(log_string));
  inclog = NULL;
  if (dest EQUALS OB_DUMP_INCLUDE)
  {
    inclog = fopen("include.log", "a");
    if (inclog)
      fprintf(inclog, "/* dumping 0x%X bytes */\n", length);
  };
  line_length = 32;
  for (i=0; i<length; i++)
  {
    sprintf (temp_string, "%02X", bytes [i]); strcat(log_string, temp_string);

    /* human-friendly hex spacing */

    if (3 EQUALS (i % 4))
    {
      insert_space = 1;
      if ((i % line_length) EQUALS (line_length-1))
        insert_space = 0;
      if (7 EQUALS (i % 8))
        insert_space = 0;
      if (insert_space)
        strcat(log_string, " ");
    };
    if (7 EQUALS (i % 8))
    {
      insert_hyphen = 1;
      if (!(3 EQUALS (i % 4)))
        insert_hyphen = 0;
      if ((i % line_length) EQUALS (line_length-1))
        insert_hyphen = 0;
      if (insert_hyphen)
        strcat(log_string, "-");
    };

    /* format as include data */
    if (inclog)
    {
      fprintf(inclog, "0X%02X", bytes [i]);
      if (i != (length-1))
        fprintf(inclog, ", ");
    };
    if ((line_length-1) == (i % line_length))
    {
      sprintf(temp_string, "\n"); strcat(log_string, temp_string);

      if (inclog)
        fprintf(inclog, "\n");
    };
  };

  if ((line_length-1) != ((length-1) % line_length))
  {
    sprintf(temp_string, "\n"); strcat(log_string, temp_string);
    if (inclog)
      fprintf(inclog, "\n");
  };

  if (dest EQUALS OB_DUMP_LOG)
  {
    if (ctx->log EQUALS NULL)
      ctx->log = stderr;
    fprintf(ctx->log, "%s", log_string);
  };
  if (dest EQUALS OB_DUMP_STDERR)
  {
    if (ctx->current_file != NULL)
      fprintf(ctx->current_file, "%s", log_string);
    else
      fprintf(stderr, "%s", log_string);
  };
  if (dest EQUALS OB_DUMP_STDOUT)
    printf("%s", log_string);
  if (dest EQUALS OB_DUMP_STRING)
  {
    if (strlen(log_string) < *out_lth)
    {
      strcpy(out_string, log_string);
      *out_lth = strlen(out_string);
    };
  };

  // clean up I/O

  fflush(stdout); fflush(stderr);
  if (ctx->log)
    fflush(ctx->log);
  if (inclog)
    fclose(inclog);

} /* ob_dump_buffer_ex */



void ob_calculate_duration
  (struct timespec *start_time,
  struct timespec *end_time,
  long *duration)

{
  int milli_start;
  int milli_end;
  int seconds;

  milli_start = start_time->tv_nsec/1000000;
  milli_end = end_time->tv_nsec/1000000;
  *duration = milli_end - milli_start;
  seconds = end_time->tv_sec - start_time->tv_sec;
  if (seconds > 0)
    *duration = *duration + 1000*seconds;
}


// was ob-util.c


void
  array_shift_left
    (OB_CONTEXT *ctx,
    unsigned char *from,
    unsigned char *to)

{ /* array_shift_left */

  int buffer_size;
  unsigned int carry;
  int i;
  unsigned int next_carry;


  buffer_size = OB_CRYPTO_AES128_LENGTH;
  if (ctx->verbosity > 9)
  {
    fprintf(stderr, "DEBUG: shift (size=%d) input:\n", buffer_size);
    for (i=0; i<buffer_size; i++)
    {
      fprintf(stderr, "%02X", from [i]);
    };
    fprintf(stderr, "\n");
  };
  carry = 0;
  for (i=(buffer_size-1); i>=0; i--)
  {
    if (from [i] & 0x80)
      next_carry = 1;
    else
      next_carry = 0;
    to [i] = (from [i] << 1) | carry;
    if (ctx->verbosity > 9)
      fprintf(stderr, "DEBUG: (%2d) from %02X to %02X c%d nc%d\n",
        i, from [i], to[i], carry, next_carry);
    carry = next_carry;
  };
  if (ctx->verbosity > 9)
  {
    fprintf(stderr, "DEBUG: shift (size=%d) results:\n", buffer_size);
    for (i=0; i<buffer_size; i++)
    {
      fprintf(stderr, "%02X", to [i]);
    };
    fprintf(stderr, "\n");
  };

} /* array_shift_left */


void
  array_xor
    (OB_CONTEXT *ctx,
    unsigned char *result,
    unsigned char *xor_left,
    unsigned char *xor_right,
    int buffer_size)

{ /* array_xor */

  int i;


  if (ctx->verbosity > 3)
    fprintf(ctx->log, "%s", ob_buffer_dump_string(ctx, xor_left, buffer_size,
" XOR (Left):"));
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "%s", ob_buffer_dump_string(ctx, xor_right, buffer_size,
"XOR (Right):"));
  for (i=0; i<buffer_size; i++)
  {
    result [i] = xor_left [i] ^ xor_right [i];
  };
  if (ctx->verbosity > 9)
  {
    fprintf(stderr, "DEBUG: xor (size=%d) results:\n", buffer_size);
    for (i=0; i<buffer_size; i++)
    {
      fprintf(stderr, "%02X", result [i]);
    };
    fprintf(stderr, "\n");
  };
  if (ctx->verbosity > 3)
    fprintf(ctx->log, "%s", ob_buffer_dump_string(ctx, result, buffer_size, "XOR Results: "));

} /* array_xor */


char
  *bcd_in_byte
    (unsigned char byte)
{
  static char bcd_digits [3];
  unsigned char hexit;


  bcd_digits [2] = 0;
  hexit = byte >> 4;
  if ((hexit >=0) && (hexit <= 9))
  {
    sprintf(bcd_digits, "%d", hexit);
  };
  hexit = byte & 0x0f;
  if ((hexit >=0) && (hexit <= 9))
  {
    sprintf(bcd_digits+1, "%d", hexit);
  };
  return(bcd_digits);
}


char
  *bcd_to_string
    (unsigned char *bcd_buffer,
    int byte_length)
{
  static char bcd_string [OB_STRING_MAX];
  int i;


  memset(bcd_string, 0, sizeof(bcd_string));
  for (i=0; i<byte_length; i++)
  {
    strcat(bcd_string, bcd_in_byte(*(bcd_buffer+i)));
  };
  return(bcd_string);
}


/*
  ob_buffer_dump_string_ex - extended version of string dump

  format - 0 adds newline like before, 1 does not.
*/


char
  *ob_buffer_dump_string_ex
    (OB_CONTEXT *ctx,
    unsigned char *buffer,
    int buffer_size,
    char *tag,
    int format)

{ /* ob_buffer_dump_string_ex */

  int i;
  static char string_buffer [8*OB_STRING_MAX];
  char tmps [OB_STRING_MAX];


  sprintf(string_buffer, "%s", tag);
  for (i=0; i<buffer_size; i++)
  {
    sprintf(tmps, "%02X", buffer [i]);
    strcat(string_buffer, tmps);
  };
  if (!format)
    strcat(string_buffer, "\n");

  return(string_buffer);

} /* ob_buffer_dump_string_ex */


char
  *ob_buffer_dump_string
    (OB_CONTEXT *ctx,
    unsigned char *buffer,
    int buffer_size,
    char *tag)

{ /* ob_buffer_dump_string */

  int i;
  static char string_buffer [8*OB_STRING_MAX];
  char tmps [OB_STRING_MAX];


  sprintf(string_buffer, "%s", tag);
  for (i=0; i<buffer_size; i++)
  {
    sprintf(tmps, "%02X", buffer [i]);
    strcat(string_buffer, tmps);
  };
  strcat(string_buffer, "\n");

  return(string_buffer);

} /* ob_buffer_dump_string */


/*
  display_PACS_data_object - displays "card contents"

  is aware of different formats.

  first arg is context
  second arg is pointer to payload
*/
void
  ob_display_PACS_data_object
  (OB_CONTEXT *ctx,
  unsigned char *credential_contents)

{ /* ob_display_PACS_data_object */

  OB_PACS_AN10957 *PACS_data_object;
  int i;


  PACS_data_object = (OB_PACS_AN10957 *)credential_contents;
  switch(ctx->pacs_data_format)
  {
  default:
    if (ctx->verbosity > 3)
      fprintf(stderr, "Unknown credential format\n");
    break;
  case OB_FORMAT_AN10957:
  fprintf(ctx->log, "PACS Data Object\n");
  fprintf(ctx->log, "----------------\n");
  fprintf(ctx->log, "Version %02X.%02X\n", PACS_data_object->version_major, PACS_data_object->version_minor);
  fprintf(ctx->log, "Customer / Site Code %s\n", bcd_to_string(PACS_data_object->site_customer, sizeof(PACS_data_object->site_customer)));
  fprintf(ctx->log, "Credential ID %s\n", bcd_to_string(PACS_data_object->credential_ID, sizeof(PACS_data_object->credential_ID)));
  fprintf(ctx->log, "Reissue Code %s\n", bcd_to_string(&(PACS_data_object->reissue_code), sizeof(PACS_data_object->reissue_code)));
  fprintf(ctx->log, "PIN Code %s\n", bcd_to_string(PACS_data_object->PIN_code, sizeof(PACS_data_object->PIN_code)));
  fprintf(ctx->log, "Customer Specific Data ");
  for (i=0; i<sizeof(PACS_data_object->customer_specific_data); i++)
    fprintf(ctx->log, "%02X", PACS_data_object->customer_specific_data [i]);
  fprintf(ctx->log, "\n");
    break;
  };
} /* ob_display_PACS_data_object */


/*
  string_buffer_hex - converts a string of hexadecimal values into a binary buffer
*/

unsigned char
  *string_buffer_hex
    (OB_CONTEXT *ctx,
    const char *buf,
    int *buf_lth)

{ /* string_buffer_hex */

  int i;
  static unsigned char octets [1024];
  int status_io;
  char tmps [3];


  tmps [2] = 0;
  *buf_lth = 0;
  for (i=0; i<strlen(buf); i=i+2)
  {
    int j;

    memcpy(tmps, buf+i, 2);
    status_io = sscanf(tmps, "%x", &j);
    if (status_io != EOF)
    {
      octets [*buf_lth] = j;
      (*buf_lth)++;
    };
  };
  return(octets);
  
} /* string_buffer_hex */


/*
  string_hex_buffer - converts a binary buffer into a printable hex string
*/
char
  *string_hex_buffer
    (OB_CONTEXT *ctx,
    unsigned char *buf,
    int buf_lth)

{ /* string_hex_to_buffer */

  int i;
  static char returned_string [OB_STRING_MAX];
  char tmps [3];


  returned_string [0] = 0;
  for (i=0; i<buf_lth; i++)
  {
    sprintf(tmps, "%02X", *(buf+i));
    strcat(returned_string, tmps);
    if (ctx->verbosity > 3)
      if (strlen(returned_string) > (OB_STRING_MAX-8))
        fprintf(stderr, "string too long\n");
  };
  return(returned_string);

} /* string_hex_to_buffer */


int ob_hex_to_binary
  (OB_CONTEXT *ctx,
  char *hex,
  unsigned char *binary,
  int *length)

{ /* ob_hex_to_binary */

  int count;
  int hexit;
  char octet_string [3];
  char *p;
  unsigned char *pbinary;
  int status;


  status = ST_OK;
  p = hex;
  pbinary = binary;
  count = strlen(hex);
  if ((count % 2) != 0)
  {
    count = count - 1;
    status = STOB_CRYPTO_CONVERT_ERROR;
  };
  while (count > 0)
  {
    memcpy(octet_string, p, 2);
    octet_string [2] = 0;
    sscanf(octet_string, "%x", &hexit);
    *pbinary = hexit;
    pbinary++;
    p = p + 2;
    count = count - 2;
  };

  return(status);

} /* ob_hex_to_binary */


int ob_init_context
  (OB_CONTEXT *ctx,
  int verbosity,
  FILE *log,
  OB_RDRCTX *rdrctx)
{

  memset(ctx, 0, sizeof(*ctx));
  ctx->log = log;
  ctx->verbosity = verbosity;
  ctx->rdrctx = rdrctx;
  memset(ctx->rdrctx, 0, sizeof(*rdrctx));
  return(ST_OK);
}

