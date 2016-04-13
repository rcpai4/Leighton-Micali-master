/* Common Headers */

#define RDM_DATA_SIZE   1024
#define DEBUG_PRINT printf(" %s %d \n ",__FUNCTION__,__LINE__)
#define FILE_READ       0

typedef struct list_node list_node_t;

struct list_node
{
    char* data;
   list_node_t* next;  
};


char* entropy_read(char* buffer, unsigned int n);
unsigned int power(unsigned int x, unsigned int y);

void entropy_create(void);

char* stringToHex(char* x, unsigned int len);
char* uint8ToString(unsigned char x);
char* uint16ToString(unsigned short int x);
char* uint32ToString(unsigned int x);
unsigned int stringToUint(char* x,unsigned int len);


void* hash_create(void);
void hash_update(void* hash_ctx,char* in_buf, unsigned int len);
void get_hash(void* hash_ctx,char* out_buf);


char* H(char* in_buf,char* out_buf, unsigned int len);

int hex_to_int(char c);
int hex_to_ascii(char c, char d);
void substr(char dest[], char src[], int offset, int len);
void to_ascii(char* dest,char *text);
void strip(char *s);
void print_buffer(char* print,unsigned int len);
char* uint16ToString_debug(unsigned short int x);



