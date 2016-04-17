/* Common Headers */

#define     RDM_DATA_SIZE   1024
#define     DEBUG_PRINT     printf(" %s %d \n ",__FUNCTION__,__LINE__)
#define     FILE_READ       0
#define     ENTROPY_SIZE    31
#define     MSG_SIZE        1024
#define     N               32

#define LMS_SHA256_N32_H10 0x02000002
#define HLMS_SHA256_N32_L2 0x01000001 

/* We choose hash algorithm based on this pre processor 
 * 1 - SHA-256 
 * 2 - BLAKE 2B
 * 4 - BLAKE 2S */

#define     SHA_256                         1
#define     BLAKE_2B                        2
#define     BLAKE_2S                        4

typedef struct list_node list_node_t;

struct list_node
{
    char* data;
   list_node_t* next;  
};

/* Entropy APIS */
void entropy_create(void);
char* entropy_read(char* buffer, unsigned int n);

/* String Manipulation APIS */
char* stringToHex(char* x, unsigned int len);
char* uint8ToString(unsigned char x,char* c1);
char* uint16ToString(unsigned short int x,char* result);
char* uint32ToString(unsigned int x,char* data);
unsigned int stringToUint(unsigned char* x,unsigned int len);

/* Hash APIS */
void* hash_create(void);
void hash_update(void* hash_ctx,char* in_buf, unsigned int len);
void get_hash(void* hash_ctx,char* out_buf);
char* H(char* in_buf,char* out_buf, unsigned int len);

/* OTHER APIs */
int hex_to_int(char c);
int hex_to_ascii(char c, char d);
void substr(char dest[], char src[], int offset, int len);
void to_ascii(char* dest,char *text);
void strip(char *s);
unsigned int power(unsigned int x, unsigned int y);
void print_buffer(char* print,unsigned int len);
unsigned int compare(char* src, char* dst, int len);
void cleanup_link_list(list_node_t*  root);

