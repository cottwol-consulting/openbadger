#define OB_SC_HIST_MAX  (8)


typedef struct apdu_record
{
  unsigned char basic_apdu [256];
} APDU_RECORD;


#define OB_SC_SUBSYSTEM_PCSC      (0)
#define OB_SC_SUBSYSTEM_SIMULATOR (1)
#define OB_SC_SUBSYSTEM_LEGIC     (2)
#define OB_SC_SUBSYSTEM_MQTT      (3)


typedef struct ob_sc_context
{
  int verbosity;
  int subsystem;
  unsigned short int message_sequence;
  void *subsystem_context;
  APDU_RECORD apdu_history [OB_SC_HIST_MAX];
} OB_SC_CONTEXT;

