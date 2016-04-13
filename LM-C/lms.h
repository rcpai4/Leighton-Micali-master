
#define HEIGHT 10

#define LMS_SHA256_N32_H10 0x02000002

unsigned int NUM_LEAF_NODES;

typedef struct lms_priv_key
{
    char I[31];
    list_node_t* priv;
    list_node_t* pub;
    unsigned int leaf_num;
    // Array of all the nodes
    list_node_t* nodes;
    char* lms_public_key; 

} lms_priv_key_t;


typedef struct lms_sig
{
    char typecode[4];
    char* lm_ots_sig;
    list_node_t* path;
} lms_sig_t;


lms_priv_key_t* create_lms_priv_key(void);

char* T(lms_priv_key_t* private_key, unsigned int j);

char* get_public_key(lms_priv_key_t* private_key);

char* lms_generate_signature(lms_priv_key_t* lms_private_key,char* message,unsigned int* sign_len);

list_node_t* get_path(lms_priv_key_t* lms_private_key, unsigned int leaf_num);

char* encode_lms_sig(char* sig, unsigned int lm_ots_len, list_node_t* path,unsigned int* lms_len);

void print_lms_sig(char* sig,unsigned int len);

void decode_lms_sig(char* sig,lms_sig_t* lms_signature,unsigned int len_sig);

unsigned int lms_verify_signature(char* sig, char* public_key, char* message, unsigned int len_sig);
