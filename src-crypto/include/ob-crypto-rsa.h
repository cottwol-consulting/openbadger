/*
  rsa internal structure

  (C)Copyright 2025-2026 Smithee Solutions LLC

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

/*
  implementation-specific context for WolfSSL

  the "internal" field of the key crypto object points to this.
*/


typedef struct ob_crypto_context_rsa
{
  int last_wolfssl_error;
  int key_length_bits;
  int key_type; //0=public 1=private
  RsaKey key;
  WC_RNG rng;
} OB_CRYPTO_CONTEXT_RSA;

