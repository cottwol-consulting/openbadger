/*
  openbadger - common definitions

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

#define EQUALS ==
#define OB_STRING_MAX      (1024)
#define OB_UID2_SIZE       (56/8) // a 1 is mifare classic a 3 is 10byte
//#define OB_DER_MAX         (8192)
#define OB_7816_BUFFER_MAX (1000)  // our buffer not one in the spec
#define OB_AES128_KEY_SIZE (128/8)
#define OB_RSA2048_KEY_SIZE (2048/8)

// various formats

#define OB_FORMAT_SIA26BIT (0)
#define OB_FORMAT_PIV      (1)
#define OB_FORMAT_AN10957  (2)
#define OB_FORMAT_LEAF     (3)
#define OB_FORMAT_Pzz1     (4)
#define OB_FORMAT_Pzz2     (5)
#define OB_FORMAT_PRIVATE  (255)

// test cases exercised (across all tests)
#define OB_TEST_VECTORS (0)
#define OB_TEST_PIV     (1)
#define OB_TEST_PKOC    (2)
#define OB_TEST_GETCERT (3)

// tool being used (in AN-10957 testing)

#define OB_TOOL_DIVUTIL (0x0001)
#define OB_TOOL_SIGUTIL (0x0002)

#define OB_NOOP      (0)
#define OB_HELP      (1)
#define OB_VERBOSITY (2)
// rfu (3)
#define OB_SETTINGS  (4)
#define OB_SELFTEST  (5)

#define OB_DUMP_STDERR  (0)
#define OB_DUMP_STDOUT  (1)
#define OB_DUMP_INCLUDE (2)
#define OB_DUMP_STRING  (3)
#define OB_DUMP_LOG     (4)

#define OB_SYSTEM_SETTINGS_FILE "/opt/tester/etc/openbadger-settings.json"
#define OB_LOCAL_SETTINGS_FILE "openbadger-settings.json"

#define ST_OK                  (   0)
#define STOB_SCARD_ERROR       (   1)
#define STOB_SCARD_CONNECT     (   2)
#define STOB_UNKNOWN_TEST_CASE (   3)
#define STOB_PCSC_TRANSMIT_1   (   4)
#define STOB_PCSC_TRANSMIT_2   (   5)
#define STOB_WRONG_TEST_CASE   (   6)
#define STOB_SELECT_RESPONSE   (   7)
#define STOB_SELRSP_TAG        (   8)
#define STOB_PKOC_AUTH         (   9)
#define STOB_SCARD_ESTABLISH   (  10)
#define STOB_NO_ARGUMENTS      (  11)
#define STOB_NOT_IMPLEMENTED   (  12)
#define STOB_SETTINGS_ERROR    (  13)
#define STOB_PIV_GETCERT       (  14)
#define STOB_GETCERT_FRAGMENT  (  15)
#define STOB_INIT_FILES        (  16)
#define STOB_SETTINGS_FILE     (  17)
#define STOB_CRYPTO_ERROR_1         (  18)
#define STOB_CRYPTO_ERROR_2         (  19)
#define STOB_CRYPTO_ERROR_3         (  20)
#define STOB_CRYPTO_ERROR_4         (  21)
#define STOB_INIT_IN_USE            (  22)
#define STOB_MALLOC                 (  23)
#define STOB_FILE_IO                (  24)
#define STOB_FILE_IO_2              (  25)
#define STOB_NO_LOGGER              (  26)
#define STOB_CRYPTO_PARSE           (  27)
#define STOB_CRYPTO_UNKNOWN_KEYTYPE (  28)
#define STOB_CRYPTO_BAD_PARAM       (  29)
#define STOB_CRYPTO_SIG_INVALID     (  30)
#define STOB_CRYPTO_SIG_1           (  31)
#define STOB_CRYPTO_SIG_2           (  32)
#define STOB_FILE_IO_3              (  33)
#define STOB_CRYPTO_FILE_OPEN       (  34)
#define STOB_CRYPTO_EC_INIT         (  35)
#define STOB_OBJECT_VALUE_TOO_LARGE (  36)
#define STOB_OBJECT_NOT_ALLOCATED   (  37)
#define STOB_CRYPTO_SIG_OID         (  38)
#define STOB_CRYPTO_OBJ_ALLOCATED   (  39)
#define STOB_CRYPTO_BAD_EC_CURVE    (  40)
#define STOB_CRYPTO_SUBSYSTEM       (  41)
#define STOB_CRYPTO_BAD_RAW_SIG     (  42)
#define STOB_CRYPTO_EC_CONVERT      (  43)
#define STOB_CRYPTO_BAD_ENC_SIG     (  42)
#define STOB_CRYPTO_SMARTCARD_1     (  43)
#define STOB_CRYPTO_SMARTCARD_2     (  43)
#define STOB_CRYPTO_CONVERT_ERROR   (  44)
#define STOB_CRYPTO_WRONG_ALGO      (  45)
#define STOB_CRYPTO_BAD_KEY_TYPE    (  46)
#define STOB_OSDP_SOCKET            (  47)
#define STOB_OSDP_CONNECT           (  48)
#define STOB_OSDP_SOCK_WRITE        (  49)
#define STOB_CRYPTO_NOT_IMPLEMENTED (  50)
#define STOB_UNSUPPORTED_JWK_CURVE  (  51)
#define STOB_CRYPTO_ERROR           (  52)
#define STOB_CRYPTO_VERIFY_FAIL     (  53)
#define STOB_CRYPTO_PRIV_IMPORT     (  54)

#define STOB_FIRST_DESFIRE          ( 100)
#define STOB_FIRST_SC               ( 200)
#define STOB_FIRST_ENCODE           ( 300)

typedef struct ob_context
{
  // generic bookkeeping
  int verbosity;
  FILE *log;
  void (*ob_log)(char *msg);

  // crypto details
    // do these need to be in the generic context?
//  unsigned char challenge_message [OB_RSA2048_KEY_SIZE];
  unsigned char secret_key [OB_AES128_KEY_SIZE];
  unsigned char iv [OB_AES128_KEY_SIZE];
  unsigned char ec_public_key [65];

  // generic crypto
  unsigned char *message;
  char message_filename [OB_STRING_MAX];

  // general bookkeeping
  int action; // action as specified by command line swtch
  unsigned long int tool_identifier;  // which "tool" is this.
  FILE *current_file;
  int pacs_data_format;
  FILE *der_out;
  char *payload_file;

  // for PCSC reader control
  int reader_index;
  char reader_name [OB_STRING_MAX];
  void *rdrctx;

  // for OSDP control
  char pd_control [OB_STRING_MAX];
  int bits_to_return;

  // 7816 and specifically general authenticate context

  unsigned char last_7816_status [2];
  int apdu_payload_max_7816;
  unsigned char algo_reference;
  unsigned char key_reference;
  int key_size;
  unsigned char challenge_type;

  // general DESFire-ish parameters
  unsigned char uid [OB_UID2_SIZE];
  int uid_size;

  void *credential_context;
} OB_CONTEXT;

// things prototyped here don't need external packages

int aes_encrypt(OB_CONTEXT *ctx, unsigned char *plaintext, unsigned char *ciphertext, unsigned char *key, int *length);
void array_shift_left(OB_CONTEXT *ctx, unsigned char *from, unsigned char *to);
void array_xor(OB_CONTEXT *ctx, unsigned char *result, unsigned char *xor_left, unsigned char *xor_right, int length);
unsigned char *base64_decode(char* cipher, int *returned_count);
char* base64_encode(char* plain, int in_count);
int ob_base64url_to_binary(OB_CONTEXT *ctx, char *base64_url, unsigned char *converted,
  int *converted_length);
char *ob_7816_status(OB_CONTEXT *ctx, int *recognized_status);
void ob_add_tag_length(unsigned char *buffer, int length, int *new_buffer_length);
char *ob_buffer_dump_string_ex(OB_CONTEXT *ctx, unsigned char *buffer, int buffer_size,
  char *tag, int format);
void ob_calculate_duration(struct timespec *start_time, struct timespec *end_time, long *duration);
int ob_command_osdp(OB_CONTEXT *ctx, char *command);
int ob_convert_ec_pubkey_DER(OB_CONTEXT *ctx, unsigned char *key_buffer, int kblth, unsigned char *marshalled_DER, int *marshalled_length);
int ob_decompress_gzip(unsigned char *out, size_t *outLen, const unsigned char *in, size_t inLen);
int ob_smartcard_command_response(OB_CONTEXT *ctx, unsigned char *input, int in_length,
  unsigned char *output, DWORD *out_length,
  unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2, unsigned char *Le, int Le_length);
int ob_smartcard_command_response_raw(OB_CONTEXT *ctx, unsigned char *x7816_buffer, int x7816_lth,
  unsigned char *r7816_buffer, DWORD *r7816_lth);
void ob_display_PACS_data_object(OB_CONTEXT *ctx, unsigned char *credential_contents);
int ob_diversify_AN10957(OB_CONTEXT *ctx);
int ob_initialize(OB_CONTEXT **initiaized_context, char *settings_filename);
int ob_initialize_pubkey_DER(OB_CONTEXT *ctx, unsigned char *key_buffer, int kblth,
  unsigned char *marshalled_DER, int *marshalled_length);
int ob_init_smartcard(OB_CONTEXT *ctx);
char *ob_buffer_dump_string(OB_CONTEXT *ctx, unsigned char *buffer, int buffer_size, char *tag);
void ob_dump_buffer(OB_CONTEXT *ctx, unsigned char *bytes, int length, int dest);
void ob_dump_buffer_ex(OB_CONTEXT *ctx, unsigned char *bytes, int length, int dest, char *out_string, int *out_lth);
int ob_hex_to_binary(OB_CONTEXT *ctx, char *hex, unsigned char *binary, int *length);
int ob_read_settings(OB_CONTEXT *ctx);
unsigned char *string_buffer_hex(OB_CONTEXT *ctx, const char *buf, int *buf_lth);
char *string_hex_buffer(OB_CONTEXT *ctx, unsigned char *buf, int buf_lth);

