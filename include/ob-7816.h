/*
  openbadger - ISO 7816 definitions

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

// generic 7816-4

#define OB_7816_APDU_PAYLOAD_MAX  (255)
#define OB_7816_SEND_LE           (0x0001)

// Global Platform APDU's

#define APDU_GET_CARD_RECOGNITION_DATA {0x80, 0xCA, 0x00, 0x66, 0x00}
#define APDU_GET_CPLC                  {0x80, 0xCA, 0x9F, 0x7F, 0x00}
#define APDU_SELECT_ANY                {0x00, 0xA4, 0x04, 0x00, 0x00}

#define APDU_GET_DATA_EF_INFO {0x00, 0xCB, 0x2F, 0x01, 0x02, 0x5C, 0x00, 0x00}


#define OB_7816_STATUS_OK         (0x9000)

