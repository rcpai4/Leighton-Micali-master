

typedef struct hlms_priv_key
{
  lms_priv_key_t* lms_priv_key_1;
  lms_priv_key_t* lms_priv_key_2;
  char*           lms_sig_1;
} hlms_priv_key_t;


typedef struct hlms_sig
{
    char typecode[4];
    char* pub2;
    char* sig1;
    char* lms_sig;

} hlms_sig_t;





hlms_priv_key_t* create_hlms_priv_key(void);

char* hlms_get_public_key(hlms_priv_key_t* hlms_private_key);

char* hlms_generate_signature(hlms_priv_key_t* hlms_private_key,char *message, unsigned int mes_len);

void hlms_init_level_2(hlms_priv_key_t *hlms_private_key);

char* encode_hlms_sig(char* pub2, char* sig1, char* lms_sig);

void print_hlms_sig(char* sig);

void decode_hlms_sig(char* sig,hlms_sig_t* hlms_signature);

unsigned int hlms_verify_signature(char* sig, char* public_key, char* message,unsigned int mes_len);

void cleanup_hlms_keys(hlms_priv_key_t* hlms_private_key);


