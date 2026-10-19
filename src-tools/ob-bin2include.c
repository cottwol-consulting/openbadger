#include <stdio.h>

int main
  (int argc,
  char *argv [])

{

  unsigned char data_buffer [32768];
  int i;
  FILE *data_file;
  FILE *include_file;
  int status_io;



  include_file = fopen("included_data.h", "w");
  data_file = fopen("raw.bin", "r");
  fprintf(include_file, "%s [] = {\n", argv [1]);
  status_io = fread(data_buffer, sizeof(data_buffer[0]), sizeof(data_buffer), data_file);
  for (i=0; i<(status_io-1); i++)
  {
    fprintf(include_file, "0x%02X,", data_buffer [i]);
    if (0 == ((1+i) % 16))
      fprintf(include_file, "\n");
  };
  fprintf(include_file, "0x%02X", data_buffer [status_io-1]);
  fprintf(include_file, "};\n");

  return(0);
}


