// ob-encode.h

#define DER_TAG_BITSTRING       (0x03)
#define DER_TAG_INTEGER         (0x02)
#define DER_TAG_OCTETSTRING     (0x04)
#define DER_TAG_OID             (0x06)
#define DER_TAG_PRINTABLESTRING (0x13)
#define DER_TAG_SEQUENCE        (0x30)
#define DER_TAG_SET             (0x31)

#if 0
#define STEAC_UNIMPLEMENTED     ( 1)
#define ST_EACE_SETTINGS_ERROR  ( 6)
#define STEAC_UNKNOWN_KEY_TYPE  ( 7)
#define STEAC_SIGN_FAILED       (10)
#define STEAC_NO_LOGGER         (11)
#define STEAC_MALLOC            (12)
#define STEAC_BUFFER            (13)
#define STEAC_ENCRYPT_ERROR     (14)
#define STEAC_CRYPTO_INIT       (15)
#define STEAC_BAD_ARG           (16)
#endif
#define STOB_FIRST_ENCODE           ( 300)
#define STOB_INT_TOO_BIG            ( 2+STOB_FIRST_ENCODE)
#define STOB_STRING_TOO_BIG         ( 3+STOB_FIRST_ENCODE)
#define STOB_TUPLE_OVERFLOW         ( 4+STOB_FIRST_ENCODE)
#define STOB_OID_TOO_SHORT          ( 5+STOB_FIRST_ENCODE)
#define STOB_OBJECT_ALLOCATE        ( 8+STOB_FIRST_ENCODE)
#define STOB_NOT_INITIALIZED        ( 9+STOB_FIRST_ENCODE)

int ob_encode_der_assemble(OB_CONTEXT *ctx, unsigned char *buffer, int *buflth, unsigned short int tag, int tag_lth,
  unsigned char *part, int partlth);
int ob_encode_der_oid_integer(OB_CONTEXT *ctx, unsigned char *tuple_buffer, int *tuple_buffer_length, unsigned int tuple);

