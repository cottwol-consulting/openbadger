// NOTE SOME CODE STUBBED OUT CHECK CONVERSION

/*
  ob-encode-prims - TLV/DER encoding primitives

  (C)2026 Cottwol Consulting

  Licensed under the Creative Commons CC0-1.0 license.
*/


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <ob-crypto.h>
#include <ob-encode.h>
static void (*ob_log)(char *msg); // for lower level logging


unsigned int oid_country [] =                 {2, 5,   4,      3};
int                        size_oid_country = 4;
unsigned int oid_commonName [] =              {1, 2, 840, 113549, 1, 1,  1};
int                     size_oid_commonName = 7;
unsigned int oid_rsaEncryption [] =           {1, 2, 840, 113549, 1, 1,  1};
int                  size_oid_rsaEncryption = 7;
unsigned int oid_sha256WithRSAEncryption [] = {1, 2, 840, 113549, 1, 1, 11};
int        size_oid_sha256WithRSAEncryption = 7;
unsigned int oid_ecdsaWithSHA256 [] =         {1, 2, 840,  10045, 4, 3,  2};
int          size_oid_ecdsaWithSHA256 =       7;


/*
  appends the encoded length to the buffer, returns length of what was encoded.
  you add the payload.
*/

void ob_append_length
  (OB_CONTEXT *ctx,
  unsigned char *buf,
  int *lth_lth,
  int partlth)

{ /* ob_append_length */

  int buf_idx;


  buf_idx = 0;
  *lth_lth=0;

  if (partlth > 127)
  {
    *(buf+buf_idx) = 0x82; // assume 2 byte length
    (*lth_lth)++; buf_idx++;
    *(buf+buf_idx) = partlth >> 8;
    (*lth_lth)++; buf_idx++;
    *(buf+buf_idx) = 0xFF & partlth;
    (*lth_lth)++; buf_idx++;
  }
  else
  {
    *(buf+buf_idx) = partlth;
    (*lth_lth)++; buf_idx++;
  };

} /* ob_append_length */


void encode_dump(unsigned char *buffer, int lth)
{
  int i;
  for(i=0; i<lth; i++)
  {
    fprintf(stderr, "%02X", buffer [i]);
    if ((i % 4) == 3)
      fprintf(stderr, " ");
  };
  fprintf(stderr, "\n");
}


int ob_encode_der_assemble
  (OB_CONTEXT *ctx,
  unsigned char *buffer,
  int *buflth,
  unsigned short int tag,
  int tag_lth,
  unsigned char *part,
  int partlth)

{ /* ob_encode_der_assemble */

  int lth_lth;
  unsigned short int nbo_tag;
  int status;


  status = ST_OK;

  // gently add the partial buffer to the entire buffer

//todo: sanity check the DER and lengths

  if (tag_lth EQUALS 1)
  {
    buffer [*buflth] = (0xff & tag);
    *buflth = 1 + *buflth;
  };
  if (tag_lth EQUALS 2)
  {
    nbo_tag = htons(tag);
    memcpy(buffer+*buflth, &nbo_tag, 2);
    *buflth = 2 + *buflth;
  };

  ob_append_length(ctx, buffer+*buflth, &lth_lth, partlth);
  *buflth = *buflth + lth_lth;

  memcpy(buffer+*buflth, part, partlth);
  *buflth = *buflth + partlth;

  return(status);

} /* ob_encode_der_assemble */


int eac_encode_der_bitstring
  (OB_CONTEXT *ctx,
  unsigned char *buffer,
  int *buflth,
  unsigned char *raw_bits,
  int raw_lth,
  int bits_in_last_octet)

{

  int actual_der_length;
  unsigned char *derp;
  int length;
  unsigned char tag;
  int status;


return(-1);
  tag = DER_TAG_BITSTRING;
fprintf(stderr, "tag %04X\n", tag);
  status = ST_OK;
  derp = buffer;
  actual_der_length = 0;
  length = raw_lth;

  {
    *derp = bits_in_last_octet;
    derp++;
    actual_der_length++;

    memcpy(derp, raw_bits, raw_lth);
    actual_der_length = actual_der_length + length; 
    *buflth = actual_der_length;
  };

  return(status);

}


//  knows the high-bit/low 6 bits scheme.

int ob_encode_der_integer
  (OB_CONTEXT *ctx,
  unsigned char *buffer,
  int *buflth,
  unsigned long int value)

{ /* ob_encode_der_integer */

  int actual_der_length;
  unsigned char *derp;
  int length;
  unsigned char octets [4];
  int offset;
  int status;
  unsigned char tag;
  unsigned int vtemp;
  int whole_length;


  status = ST_OK;
  derp = buffer;
  actual_der_length = 0;
  vtemp = value;
  tag = DER_TAG_INTEGER;
  if (value > 0xFFFFFFFF)
    status = STOB_INT_TOO_BIG;
  if (status EQUALS ST_OK)
  {
    length = 1;
    octets [3] = 0x000000FF & value;
    vtemp = vtemp >> 8;
    if (vtemp > 0)
    {
      octets [2] = 0x000000FF & vtemp;
      length++;
      vtemp = vtemp >> 8;
      if (vtemp > 0)
      {
        octets [1] = 0x000000FF & vtemp;
        length++;
        vtemp = vtemp >> 8;
        if (vtemp > 0)
        {
          octets [0] = 0x000000FF & vtemp;
          length++;
        };
      };
    };
  };
  if (status EQUALS ST_OK)
  {
    *derp = tag;
    derp++; actual_der_length++;
    *derp = length;
    derp++; actual_der_length++;

    // copy whatever encoded bytes worked.

    {
      whole_length = 4;
      offset = whole_length - length;
      memcpy(derp, octets+offset, length);
    };

    actual_der_length = actual_der_length + length; 
    *buflth = actual_der_length;
  };
  return(status);

} /* ob_encode_der_integer */


/*
  eac_encode_der_oid - encode an integer for use in an OID

  inputs
    buffer - pointer to where to store answer
    buflth - pointer to length, on input should be max
    oid - array of oid tuple values
    oid_length - number of tuples
  output
    buflth - pointer to length, will be set to actual upon return
*/
int eac_encode_der_oid
  (OB_CONTEXT *ctx,
  unsigned char *buffer,
  int *buflth,
  unsigned int *oid,
  int oid_length)

{ /* eac_encode_der_oid */

  int done;
  int max_result_length;
  int next; // running pointer into output buffer
  int next_tuple;
  int status;
  int t_lth;
  unsigned char tuple_buffer [OB_DER_MAX];


  status = ST_OK;
  max_result_length = *buflth;
  t_lth = 0;
  next = 0;
  next_tuple = 0;
  ob_log = ctx->ob_log;

  // pre-pend tag and spacer for length
  buffer [next] = DER_TAG_OID;
  next = next + 1 + 1; // assumes OID is <128 octets

  done = 0;

  // first two (there must be at least 3) are 40+first + second
  if (oid_length < 3)
  {
    status = STOB_OID_TOO_SHORT;
    done = 1;
  }
  else
  {
    buffer [next] = (oid [0] * 40) + oid [1];
    next_tuple = 2;
    next = next + 1;
  };

  while (!done)
  {
    // grab a tuple, encode it.
    status = ob_encode_der_oid_integer(ctx, tuple_buffer, &t_lth, oid [next_tuple]);
    if (status != ST_OK)
      done = 1;

    if (status EQUALS ST_OK)
    {
      // better fit
      if ((next + t_lth) > max_result_length)
        status = STOB_TUPLE_OVERFLOW;

      // append to the buffer
      memcpy(buffer+next, tuple_buffer, t_lth);
      next = next + t_lth;

      next_tuple++;
      if (next_tuple EQUALS oid_length)
        done = 1;
    };

    // stuff in length
    buffer [1] = next - 2;
    if (ctx->verbosity > 9)
      encode_dump(buffer, next);
  };
  if (status EQUALS ST_OK)
    *buflth = next;

  return(status);

} /* eac_encode_der_oid */


/*
  ob_encode_der_oid_integer - encode a single integer tuple of an OID

  if < 128 use value
  if > 127 set high bit of first octet, use low 7 bits of that octet and the next octet,
    repeating high bit setting if necessary
*/

int ob_encode_der_oid_integer
  (OB_CONTEXT *ctx,
  unsigned char *tuple_buffer,
  int *tuple_buffer_length,
  unsigned int tuple)

{ /* ob_encode_der_oid_integer */

  unsigned char chunk [OB_DER_MAX];
  int i;
  int status;
  int tcount;
  unsigned int ttmp;


  status = ST_OK;
  ttmp = tuple; // running value after shifting
  tcount = 0; // number of octets used
  if (ttmp < 128)
  {
    *tuple_buffer_length = 1;
    tuple_buffer [tcount] = ttmp;
  }
  else
  {
    while (ttmp > 0)
    {
      chunk [tcount] = 0x7f & ttmp;
      if (ctx->verbosity > 3)
        fprintf(stderr, "DEBUG: chunk %02X ttmp %X(%d.) tcount %d.\n",
          chunk [tcount], ttmp, ttmp, tcount);
      ttmp = ttmp >> 7;
      tcount++;
    };
    for (i=0; i<tcount; i++)
    {
      if (i > 0)
        chunk [i] = 0x80 | chunk [i];
      if (ctx->verbosity > 3)
        fprintf(stderr, "DEBUG: chunk[%d] %02X goes to tuple_buffer[%d]\n",
  i, chunk[i], tcount-1-i);
      tuple_buffer [tcount-1-i] = chunk [i];
    };
    *tuple_buffer_length = tcount;
  };
  return(status);

} /* ob_encode_der_oid_integer */


/*
  accepts a printable string, returns DER encoding.

  only works up to 127 characters
  assumes IA-5/USASCII/printable not unicode
*/

int leace_encode_der_PrintableString
  (OB_CONTEXT *ctx,
  unsigned char *buffer,
  int *buflth,
  char *string)

{ /* der_encode_der_PrintableString */

  int actual_der_length;
  unsigned char *derp;
  int length;
  unsigned char tag;
  int status;


  status = ST_OK;
  derp = buffer;
  actual_der_length = 0;
  tag = DER_TAG_PRINTABLESTRING;
  length = strlen(string);
  if (length > 127)
    status = STOB_STRING_TOO_BIG;
  if (status EQUALS ST_OK)
  {
    *derp = tag;
    derp++; actual_der_length++;
    *derp = length;
    derp++; actual_der_length++;
    strcpy((char *)derp, string);
    actual_der_length = actual_der_length + length; 
    *buflth = actual_der_length;
  };
  return(status);

} /* leac_encode_der_PrintableString */


int eac_encode_der_sequence
  (OB_CONTEXT *ctx,
  unsigned char *sequence_buffer,
  int *seqbuflth,
  unsigned char *assembled,
  int asmlth)

{ /* eac_encode_der_sequence */

  int payload_offset;
  int sequence_length;


  sequence_length = 0;
  sequence_buffer [0] = DER_TAG_SEQUENCE;
  payload_offset = 2;
  if (asmlth < 128)
  {
    sequence_buffer [1] = asmlth;
    memcpy(sequence_buffer + payload_offset, assembled, asmlth);
    sequence_length = sequence_length + 2 + asmlth;
  };
  if (asmlth > 127)
  {
    payload_offset = 4;
    sequence_buffer [1] = 0x82;
    sequence_buffer [2] = asmlth >> 8;
    sequence_buffer [3] = 0xff & asmlth;
    memcpy(sequence_buffer + payload_offset, assembled, asmlth);
    sequence_length = sequence_length + payload_offset + asmlth;
  };
  *seqbuflth = sequence_length;
 
  return(ST_OK);

} /* eac_encode_der_sequence */


int leace_encode_der_set
  (OB_CONTEXT *ctx,
  unsigned char *set_buffer,
  int *setbuflth,
  unsigned char *assembled,
  int asmlth)

{ /* leace_encode_der_set */

  int payload_offset;


  set_buffer [0] = DER_TAG_SET;
  payload_offset = 2;
  if (asmlth < 128)
  {
    set_buffer [1] = asmlth;
    memcpy(set_buffer + payload_offset, assembled, asmlth);
  };
  if (asmlth > 127)
  {
    payload_offset = 4;
    set_buffer [1] = 0x82;
    set_buffer [2] = asmlth >> 8;
    set_buffer [3] = 0xff & asmlth;
  };
  memcpy(set_buffer + payload_offset, assembled, asmlth);
  *setbuflth = asmlth + payload_offset;
 
  return(ST_OK);
}


#if 0
int leace_encode_der_subject_set
  (OB_CONTEXT *ctx,
  unsigned char *buffer,
  int *buflth,
  unsigned int *oid,
  int oid_length,
  char *string)

{ /* leace_encode_der_subject_set */

  int available;
  unsigned char b_oid [OB_DER_MAX];
  int b_oid_lth;
  unsigned char b_seq [OB_DER_MAX];
  int b_seq_idx;
  int b_seq_lth;
  unsigned char b_seq_assembled [OB_DER_MAX];
  int b_seqa_lth;
  unsigned char b_set [OB_DER_MAX];
  int b_set_lth;
  unsigned char b_string [OB_DER_MAX];
  int b_str_lth;
  int status;

  
  status = ST_OK;

  // init sequence buffer
  b_seq_lth = sizeof(b_seq);

  // init set buffer
  b_set_lth = sizeof(b_set);

  // encode the object identifer
  b_oid_lth = sizeof(b_oid);
  status = eac_encode_der_oid(ctx, b_oid, &b_oid_lth, oid, oid_length);

  if (status EQUALS ST_OK)
  {
    if (ctx->verbosity > 3)
      encode_dump(b_oid, b_oid_lth);
    available = sizeof(b_seq);
    b_seq_lth = available;
    b_seq_idx = 0;
    status = ob_encode_der_assemble(ctx, b_seq, b_seq_idx, &available, b_oid, b_oid_lth);
    status = ob_encode_der_assemble(ctx, b_seq, &b_seq_index, DER_TAG_OID, 1, 
  int tag_lth,
  unsigned char *part,
  int partlth)




    b_seq_lth = b_seq_idx + available;
    b_seq_idx = b_seq_lth;
    if (ctx->verbosity > 3)
      encode_dump(b_seq, b_seq_lth);
  };

  if (status EQUALS ST_OK)
  {
    b_str_lth = sizeof(b_string);
    status = leace_encode_der_PrintableString(ctx, b_string, &b_str_lth, string);
  };
  if (status EQUALS ST_OK)
  {
    if (ctx->verbosity > 3)
      encode_dump(b_string, b_str_lth);
    available = sizeof(b_seq) - b_seq_idx;
    status = ob_encode_der_assemble(ctx, b_seq, b_seq_idx, &available, b_string, b_str_lth);
    b_seq_lth = available;
    b_seq_idx = b_seq_lth;
    if (ctx->verbosity > 3)
      encode_dump(b_seq, b_seq_lth);
  };

  if (status EQUALS ST_OK)
  {
    b_seqa_lth = 0;
    status = eac_encode_der_sequence(ctx, b_seq_assembled, &b_seqa_lth, b_seq, b_seq_lth);
    if (status EQUALS ST_OK)
      status = leace_encode_der_set(ctx, b_set, &b_set_lth, b_seq_assembled, b_seqa_lth);
    if (status EQUALS ST_OK)
    {
      memcpy(buffer, b_set, b_set_lth);
      *buflth = b_set_lth;
    };
  };

  return(status);

} /* eac_encode_der_subject_set */
#endif


void eac_encode_dump_buffer
  (char *tag,
  unsigned char *buffer,
  int lth)

{ /* eac_encode_dump_buffer */

  int chunks;
  int i;
  char log_message [16384];
  char part [1024];


  if (strlen(tag) > 0)
  {
    sprintf(log_message, "%s ", tag);
    (*ob_log)(log_message);
  };
  chunks = 0;
  log_message [0] = 0;
  for(i=0; i<lth; i++)
  {
    if (strlen(log_message) < (sizeof(log_message) - 6))
    {
      sprintf(part, "%02X", buffer [i]);
      strcat(log_message, part);
      if ((i % 4) == 3)
      {
        chunks++;
        if (0 EQUALS (chunks % 8))
          strcat(log_message, "\n ");
        else
          strcat(log_message, " ");
      };
    };
  };
  strcat(log_message, "\n");
  (*ob_log)(log_message);

} /* eac_encode_dump_buffer */


int ob_encode_free_object
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *object)

{ /* ob_encode_free_object */

  int status;


  status = STOB_OBJECT_ALLOCATE;
  if (object)
  {
    if (object->internal)
    {
      free(object->internal);
      status = ST_OK;
    };
  };
  return(status);

} /* ob_encode_free_object */


int eac_encode_hex_string_to_bytes
  (char *hex_string,
  unsigned char *raw_bytes,
  int *returned_length)

{ /* eac_encode_hex_string_to_bytes */

  int done;
  unsigned int octet;
  char octet_string [3];
  char *p;
  int status;


  status = ST_OK;
  raw_bytes [0] = 0;
  *returned_length = 0;

  p = hex_string;
  done = 0;
  while (!done)
  {
    if (strlen(p) < 2)
      done = 1;
    if (!done)
    {
      octet_string [0] = *p;
      octet_string [1] = *(p+1);
      octet_string [2] = 0;
      sscanf(octet_string, "%x", &octet);
      raw_bytes [*returned_length] = octet;
      (*returned_length) ++;
      p = p+2;
    };
  };
  return(status);

} /* eac_encode_hex_string_to_bytes */

