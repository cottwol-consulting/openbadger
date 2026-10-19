#include <stdio.h>
#include <string.h>
#include <time.h>


#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>


#include <ob-7816.h>
#include <openbadger-common.h>
#include <openbadger-version.h>


int main
  (int argc,
  char *argv [])

{ /* main for ob-hex2bin */

  FILE *bf;
  unsigned char binary_buffer [2048];
  int in_length;
  int length;
  OB_CONTEXT my_ob_context;
  unsigned char *new_buffer;
  char string_buffer [8192];

  memset(&my_ob_context, 0, sizeof(my_ob_context));
  fread(string_buffer, sizeof(string_buffer[0]), sizeof(string_buffer), stdin);
  in_length = strlen(string_buffer);
  fprintf(stderr, "Input string length is %d\n", in_length);
  length = sizeof(binary_buffer);
  new_buffer = string_buffer_hex(&my_ob_context, string_buffer, &length);
  memcpy(binary_buffer, new_buffer, length);
  bf = fopen("data.bin", "w");
  fwrite(binary_buffer, sizeof(binary_buffer [0]), length, bf);
  return(0);

} /* main for ob-hex2bin */

