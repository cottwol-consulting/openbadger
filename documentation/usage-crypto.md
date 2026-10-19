
ob_crypto_verify_signature - verify a signature
Inputs
  openbadger context
  signer key openbadger object
    raw field is the DER of the signer key
    key_parameters [0] is the format.  0=DER 1=X9.63 
  message signature matches, message length
  signature openbadger object
    if raw set it's the raw
    if enc set it's the DER

\newpage {}

# x. Dual-Key Cryptograph #

# x.1 Crypto Object Contents #

```
#define OB_CKPARM_FORMAT (0) 
#define OB_CKPARM_ALGO (1) 
#define OB_CKPARM_SIZE_CURVE (2)
#define OB_CKPARM_PK_ACTION  (3)
#define OB_CKPARM_PK_PUBPRIV (4)
```

# x.1 Object Management #

Initialize a key regardless of type with this.
key_parameters [___OB_CKPARAM_ALGO___] must be set to the algorithm type.

```
  int ob_crypto_pk_initialize(OB_CONTEXT *ctx, OB_CRYPTO_OBJECT *key);
```

# x.1 signing

# x.2 verifying

# x.3 encrypting

# x.4 decrypting

// message contains ciphertext in blah and cleartext in decoded-blah
int ob_crypto_pk_decrypt
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key,
  OB_CRYPTO_OBJECT *message)

int ob_crypto_pk_encrypt
  (OB_CONTEXT *ctx,
  OB_CRYPTO_OBJECT *key,
  OB_CRYPTO_OBJECT *message)


