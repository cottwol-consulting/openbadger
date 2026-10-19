/*
  ob-piv-utils - compression etc. routines for PIV-ish data

  (C)Copyright 2017-2026 Smithee Solutions LLC

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


#include <stddef.h>
#include <memory.h>
#include <stdio.h>


#include <zlib.h>


#define u8 unsigned char


int
  ob_decompress_gzip
    (unsigned char *out,
    size_t *outLen,
    const unsigned char *in,
    size_t inLen)

{ /* ob_decompress_gzip */

  /* Since uncompress does not offer a way to make it uncompress gzip... manually set it up */
  z_stream gz;
  int err;
  int window_size = 15 + 0x20;


  memset(&gz, 0, sizeof(gz));

  gz.next_in = (u8*)in;
  gz.avail_in = inLen;
  gz.next_out = out;
  gz.avail_out = *outLen;
  gz.zalloc = Z_NULL;
  gz.zfree = Z_NULL;
  gz.opaque = Z_NULL;

  err = inflateInit2(&gz, window_size);
  if (err == Z_OK)
  {
    err = inflate(&gz, Z_FINISH);
    if (err != Z_STREAM_END)
    {
      inflateEnd(&gz);
    }
    if ((err == Z_BUF_ERROR) || (err == Z_STREAM_END))
    {
      *outLen = gz.total_out;

      err = inflateEnd(&gz);
    };
  };
  return (err);

} /* ob_decompress_gzip */

