/*
  ob-cert-read - reads a cert with the local library and outputs a json representation on stdout
*/

#include <time.h>
#include <string.h>
#include <stdlib.h>


#include <mbedtls/x509_crt.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <openbadger-common.h>
#include <openbadger-version.h>
#include <ob-crypto.h>

/*
  object raw is the input
  object encoded is results
*/

typedef struct mbedtls_internal
{
  mbedtls_x509_crt certificate_chain;
} OB_MBEDTLS_INTERNAL;
int find_oid(unsigned char *oid_ptr, int *known_oid);
int print_value(unsigned char *der);


int bitstring_dump_value
  (unsigned char *der)

{
  int der_length;
  int i;


  der_length = *(1+der);
  // +2 to get past tlv header, +1 to get past bit offset
  for (i=0; i<der_length; i++)
    fprintf(stderr, "%02X", *(i+der+2+1));
  fprintf(stderr, "(hex)\n");
  return(0);
}


int dump_value
  (unsigned char *der)

{ 
  int der_length;
  int i;


  der_length = *(1+der);
  fprintf(stderr, " %02X %02X", *der, der_length);
  for (i=0; i<der_length; i++)
    fprintf(stderr, " %02X", *(i+der+2));
  fprintf(stderr, "\n");

  return(0);
}


int extract_subject
  (OB_CONTEXT *ctx,
  unsigned char *subj_der,
  int subj_der_lth,
  char *translation)

{ /* extract_subject */

  int der_length;
  int i;
  int known_oid;
  int more;
  int oid_length;
  unsigned char *oid_ptr;
  unsigned char *p;
  int remaining_length;
  int set_length;
  int status;
  char tmps [1024];


  status = ST_OK;
  p = subj_der;
  remaining_length = subj_der_lth;

  if (*p != 0x30)
    status = -1; // bad outer tag
  if (status EQUALS ST_OK)
  {
    p++;
    der_length = *p;
    p++;
    remaining_length = remaining_length - 2;
    if (der_length != remaining_length)
      status = -2; //outer length not consistent
  };
  if (status EQUALS ST_OK)
  {
    more = 1;
    while (more)
    {
      // grab the "Set"
      if (*p != 0x31)
        status = -3; // expected Set tag
      if (status EQUALS ST_OK)
      {
        p++;
        set_length = *p;
        p++;
// skip sequence
        p = p + 2;
        oid_ptr = p;
        status = find_oid(oid_ptr, &known_oid);
        if (*p != 0x06)
          status = -5; //not oid tag
        if (status EQUALS ST_OK)
        {
          p++;
          oid_length = *p;
          p = p + 1 + oid_length; // now points at value
          switch(known_oid)
          {
          default:
            status = -4;
            break;
          case OID_COMMON_NAME:
            if (ctx->verbosity > 3)
            {
              fprintf(stderr,
"      commonName:");
              dump_value(p);
              print_value(p);
            };
            // it's printable, copy it to translation as-is
            strcat(translation, ",\n\"common-name\":\"");
            strncat(translation, (char *)(p+2), *(p+1));
            strcat(translation, "\"");
            break;
          case OID_DESCRIPTION:
            if (ctx->verbosity > 3)
            {
              fprintf(stderr,
"     description:");
              dump_value(p);
              print_value(p);
            };
            strcat(translation, ",\n\"description\":\"");
            strncat(translation, (char *)(p+2), *(p+1));
            strcat(translation, "\"");
            break;
          case OID_SERIAL_NUMBER:
            if (ctx->verbosity > 3)
            {
              fprintf(stderr,
"    serialNumber:");
              dump_value(p);
              print_value(p);
            };
            strcat(translation, ",\n\"serial-number\":\"");
            strncat(translation, (char *)(p+2), *(p+1));
            strcat(translation, "\"");
            break;
          case OID_UNIQUE_IDENTIFIER:
            if (ctx->verbosity > 3)
            {
              fprintf(stderr,
"uniqueIdentifier:");
              dump_value(p);
              bitstring_dump_value(p);
            };
            strcat(translation, ",\n\"unique-identifier\":\"");
            for (i=0; i<*(p+1) - 1; i++)
            {
              sprintf(tmps, "%02x", *(p+3+i));
              strcat(translation, tmps);
            };
            strcat(translation, "\"");
            strcat(translation, ",\n\"unique-identifier-bitlength\":\"");
            sprintf(tmps, "%d", (*(p+1))*8 - *(p+2));
            strcat(translation, tmps);
            strcat(translation, "\"");
            break;
          };
          der_length = *(p+1);
          p = p + 2 + der_length; // skip past value
        };

        remaining_length = remaining_length - 2 - set_length;
        if (remaining_length < 7) // calculated absolute minimum for a subjectName Set
          more = 0;
        if (status != ST_OK)
          more = 0;
      };
    };
    strcat(translation, "}");
  };

  return(status);

} /* extract_subject */


unsigned char DER_OID_COMMON_NAME [] =
  {0x06, 0x03, 0x55, 0x04, 0x03};
unsigned char DER_OID_DESCRIPTION [] =
  {0x06, 0x03, 0x55, 0x04, 0x0D};
unsigned char DER_OID_SERIAL_NUMBER [] =
  {0x06, 0x03, 0x55, 0x04, 0x05};
unsigned char DER_OID_UNIQUE_IDENTIFIER [] =
  {0x06, 0x03, 0x55, 0x04, 0x2D};

int find_oid
  (unsigned char *oid_ptr,
  int *known_oid)

{
  int status;


  status = ST_OK;
  *known_oid = OID_UNKNOWN;
  if (!memcmp(oid_ptr, DER_OID_COMMON_NAME, sizeof(DER_OID_COMMON_NAME)))
    *known_oid = OID_COMMON_NAME;
  if (!memcmp(oid_ptr, DER_OID_DESCRIPTION, sizeof(DER_OID_DESCRIPTION)))
    *known_oid = OID_DESCRIPTION;
  if (!memcmp(oid_ptr, DER_OID_SERIAL_NUMBER, sizeof(DER_OID_SERIAL_NUMBER)))
    *known_oid = OID_SERIAL_NUMBER;
  if (!memcmp(oid_ptr, DER_OID_UNIQUE_IDENTIFIER, sizeof(DER_OID_UNIQUE_IDENTIFIER)))
    *known_oid = OID_UNIQUE_IDENTIFIER;
  return(status);
}


int print_value
  (unsigned char *der)
{
  int der_length;
  int i;


  der_length = *(1+der);
  for (i=0; i<der_length; i++)
    fprintf(stderr, "%c", *(i+der+2));
  fprintf(stderr, "\n");
  return(0);
}



int ob_crypto_cert_parse
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *certificate)

{ /* ob_crypto_cert_parse */

  int i;
  OB_MBEDTLS_INTERNAL *internal;
  int item_length;
  unsigned char *p;
  unsigned char public_key_der_buffer [32768];
  int status;
  int status_mbedtls;
  int subject_raw_length;
  unsigned char *subjectName_der;
  char tmps [1024];


  status = ST_OK;
  memset(certificate->encoded, 0, sizeof(certificate->enc_lth));

  certificate->internal = malloc(sizeof(OB_MBEDTLS_INTERNAL));
  internal = certificate->internal;
  memset(internal, 0, sizeof(*internal));

  // init cert chain to proper empty
  mbedtls_x509_crt_init(&(internal->certificate_chain));

  status_mbedtls = mbedtls_x509_crt_parse_der
    (&(internal->certificate_chain), certificate->raw, certificate->raw_lth);
  if (ctx->verbosity > 3)
    fprintf(stderr, "mbedtls_x509_crt_parse_der status was %d.\n", status_mbedtls);

  // get the public key

  status_mbedtls = mbedtls_pk_write_pubkey_der(&(internal->certificate_chain.pk), public_key_der_buffer, sizeof(public_key_der_buffer));
// if ok
  {
    p = public_key_der_buffer + sizeof(public_key_der_buffer) - status_mbedtls;
    sprintf(tmps, "{\"_impressum\":\"%s\"", OPENBADGER_VERSION);
    strcat((char *)(certificate->encoded), tmps);
    strcat((char *)(certificate->encoded), ",\n\"public-key\":\"");
    for (i=0; i<status_mbedtls; i++)
    {
      sprintf(tmps, "%02X", *(p+i));
      strcat((char *)(certificate->encoded), tmps);
    };
    strcat((char *)(certificate->encoded), "\"");

    // get the TBS

    p = internal->certificate_chain.tbs.p;
    item_length = internal->certificate_chain.tbs.len;
    strcat((char *)(certificate->encoded), ",\n\"to-be-signed\":\"");
    for (i=0; i<item_length; i++)
    {
      sprintf(tmps, "%02X", *(p+i));
      strcat((char *)(certificate->encoded), tmps);
    };
    strcat((char *)(certificate->encoded), "\"");
  };


  subject_raw_length = internal->certificate_chain.subject_raw.len;
  certificate->aux_lth = subject_raw_length;
  subjectName_der = internal->certificate_chain.subject_raw.p;
  memcpy(certificate->aux, subjectName_der, subject_raw_length);
  if (ctx->verbosity > 3)
  {
    fprintf(stderr, "Subject (raw):\n");
    for (i=0; i<subject_raw_length; i++)
      fprintf(stderr, " %02X", *(i+subjectName_der));
    fprintf(stderr, "\n");
  };

  status = extract_subject(ctx, certificate->aux, certificate->aux_lth, (char *)(certificate->encoded));
  certificate->enc_lth = strlen((char *)(certificate->encoded));
  return(status);

} /* ob_crypto_cert_parse */

