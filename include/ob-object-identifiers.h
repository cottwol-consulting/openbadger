unsigned char DER_OID_COMMON_NAME [] =
  {0x06, 0x03, 0x55, 0x04, 0x03};
unsigned char DER_OID_DESCRIPTION [] =
  {0x06, 0x03, 0x55, 0x04, 0x0D};
unsigned char DER_OID_SERIAL_NUMBER [] =
  {0x06, 0x03, 0x55, 0x04, 0x05};
unsigned char DER_OID_UNIQUE_IDENTIFIER [] =
  {0x06, 0x03, 0x55, 0x04, 0x2D};
#if 0
OID(DER): 01 03 06 01 04 01 AFBA 02 05 00 Value(DER): 01 01 FF
OID(DER): 01 03 06 01 04 01 AFBA 08 08 Value(DER): 0C 0E 30 30 30 30 31 30 30 30 30 30 30 30 33 33
OID(DER): 01 03 06 01 04 01 AFBA 08 02 Value(DER): 04 04 0A A1 63 AC
OID(DER): 01 03 06 01 04 01 AFBA 08 01 Value(DER): 04 10 61 96 F4 46 42 07 48 35 A9 3E 87 CB 14 A0 40 F2
#endif

unsigned int int_oid_country [] =                 {2, 5,   4,      3};
int        size_int_oid_country = 4;
unsigned int int_oid_commonName [] =              {1, 2, 840, 113549, 1, 1,  1};
int        size_int_oid_commonName = 7;
unsigned int int_oid_rsaEncryption [] =           {1, 2, 840, 113549, 1, 1,  1};
int        size_int_oid_rsaEncryption = 7;
unsigned int int_oid_sha256WithRSAEncryption [] = {1, 2, 840, 113549, 1, 1, 11};
int        size_int_oid_sha256WithRSAEncryption = 7;
unsigned int int_oid_ecdsaWithSHA256 [] =         {1, 2, 840,  10045, 4, 3,  2};
int        size_int_oid_ecdsaWithSHA256 = 7;

// PK-PACS OID's

unsigned short int int_oid_pkpacs_uid1 [] =
  {0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0xE925, 0x08, 0x02};
unsigned short int int_oid_pkpacs_uid2 [] =
  {0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0xE925, 0x08, 0x03};
unsigned short int int_oid_pkpacs_uuid [] =
  {0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0xE925, 0x08, 0x01};

  // WARNING added a null to make callback matcher work
unsigned short int int_oid_taglio_pkpacs_csn [] =
  {0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0xAFBA, 0x08, 0x08, 0};
unsigned short int int_oid_taglio_pkpacs_uid1 [] =
  {0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0xAFBA, 0x08, 0x02, 0};
unsigned short int int_oid_taglio_pkpacs_uid2 [] =
  {0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0xAFBA, 0x08, 0x03, 0};
unsigned short int int_oid_taglio_pkpacs_uuid [] =
  {0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0xAFBA, 0x08, 0x01, 0};

