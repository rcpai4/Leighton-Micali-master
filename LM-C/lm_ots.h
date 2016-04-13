
#define N  32
#define P  34
#define W  8
#define LS 0

#define D_ITER  0x00 // In the iterations of the LM-OTS algorithms
#define D_PBLC  0x01 // when computing the hash of all of the iterates in the LM-OTS algorithm
#define D_MESG  0x02 // when computing the hash of the message in the LMOTS algorithms
#define D_LEAF  0x03 // when computing the hash of the leaf of an LMS tree
#define D_INTR  0x04 // when computing the hash of an interior node of an LMS tree


#define LMOTS_SHA256_N32_W8  0x08000008 // typecode for lm-ots with n=32, w=8

typedef struct lm_ots_sig
{
    char C[N];
    char I[31];
    char q[4];
    list_node_t* y;    
} lm_ots_sig_t;

list_node_t* generate_private_key(void);

char* generate_public_key(list_node_t* private_key, char* I, char* q);

char* encode_lmots_signature(char* C, char* I, char* q,list_node_t*  y,unsigned int* sign_len);


char* checksum(unsigned char *x, unsigned int len);

void print_lmots_signature(char* lmots_signature);
void decode_lmots_sig(char *sig, lm_ots_sig_t* decoded_sig);
unsigned int bytes_in_lmots_sig(void);

char* lmots_generate_signature(list_node_t* lm_ots_private_key, char* I,char* q, char* message,unsigned int * len);
unsigned int  lmots_verify_signature(char*  public_key,char * sig, char* message);
char* lmots_sig_to_public_key(char *sig, char* message);
unsigned int compare(char* src, char* dst, int len);


