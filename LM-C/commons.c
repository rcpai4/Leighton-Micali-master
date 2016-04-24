#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

//For SHA 256  
#include "sha2.h"
//For BLAKE 
#include "blake2b.h"
#include "blake2s.h"


//User defined headers
#include "commons.h"


FILE *fp_file = NULL;
#if FILE_READ
char file_buff[1024]; 
#endif


/*TODO: This needs to be a input param */
unsigned int chosen_has_algo        = SHA_256;
void entropy_create(void)
{
    srand(time(0));
#if FILE_READ
    fp_file = fopen("inputfile_lms","r");
#else
    fp_file = fopen("/dev/urandom", "r");
#endif
}

char* entropy_read(char* buffer, unsigned int n)
{
#if FILE_READ
    fgets(file_buff,sizeof file_buff,fp_file);
    strip(file_buff);
    to_ascii(buffer,file_buff);
#else
    if(n == fread(buffer, 1, n, fp_file))
        return buffer;
    //fclose(fp);
#endif
    return buffer;
}


char* uint32ToString(unsigned int x,char* data)
{
    char c1 = 0,c2 = 0,c3 = 0,c4 =0;
    c4 = (char)(x & 0xff);
    x = x >> 8;
    c3 = (char)(x & 0xff);
    x = x >> 8;
    c2 = (char)(x & 0xff);
    x = x >> 8;
    c1 = (char)(x & 0xff);
    memcpy(data,&c1,sizeof(char));
    memcpy(data + (1),&c2,sizeof(char));
    memcpy(data + (2),&c3,sizeof(char));
    memcpy(data + (3),&c4,sizeof(char));
    data[4] = '\0';
    return data;
}

char* uint16ToString(unsigned short int x,char* result)
{
    char c1 = 0,c2 = 0;
    //char* result =(char*) malloc(3 * sizeof(char));
    c2 = (char)(x & 0xff);
    x = x >> 8;
    c1 = (char)(x & 0xff);
    memcpy(result,&c1,1);
    memcpy(result + 1,&c2,1);
    result[2] = '\0';
    return result;
}

char* uint8ToString(unsigned char x,char* c1)
{
    //char* c1 = (char*) malloc(sizeof(unsigned char));
    c1[0] = (char)(x & 0xff);
    c1[1] = '\0';
    return c1;
}

unsigned int stringToUint(unsigned char* x,unsigned int len)
{
    unsigned int sum = 0;
    unsigned int i = 0;
    for( i = 0; i < len; i++)
    {
        sum = sum * 256 + x[i];
    }
    return sum;    
}


char* stringToHex(char* x, unsigned int len)
{     
    static const char* const lut = "0123456789ABCDEF";
    char* y = x;    
    size_t i = 0;
    char* output = (char*) malloc((2*len + 1)*sizeof(char)); 
    memset(output,0,sizeof(2*len*sizeof(char)) + 1);
	
	for(i=0; i<len; i++) {
        const unsigned char c = y[i];
		output[i*2] = lut[c >> 4];
		output[i*2+1] = lut[c & 0x0f]; //nibbleToChar(bytes[i] & 0x0f);
	}
    output[2*i] = '\0';
	return output;    
}

void* hash_create(void)
{
    void* hash_ctx = NULL;
    if(chosen_has_algo == SHA_256)
    {
        hash_ctx = (SHA256_CTX*)malloc(sizeof(SHA256_CTX));
        SHA256_Init(hash_ctx);
    }
    else if(chosen_has_algo == BLAKE_2B)
    {
        hash_ctx = (blake2b_ctx*) malloc(sizeof(blake2b_ctx));
        if(blake2b_init(hash_ctx, N, NULL, 0))
            return NULL;
    }
    else if(chosen_has_algo == BLAKE_2S)
    {
        hash_ctx = (blake2s_ctx*) malloc(sizeof(blake2s_ctx));
        if(blake2s_init(hash_ctx, N, NULL, 0))
            return NULL;
    }    

    return (void*)hash_ctx;

}

void hash_update(void* hash_ctx,char* in_buf, unsigned int len)
{
    if(chosen_has_algo == SHA_256)
    {
        SHA256_Update((SHA256_CTX*)hash_ctx, (unsigned char*)in_buf, len);
    }
    else if(chosen_has_algo == BLAKE_2B)
    {
        blake2b_update(hash_ctx, in_buf, len);         
    }
    else if(chosen_has_algo == BLAKE_2S)
    {
        blake2s_update(hash_ctx, in_buf, len);        
    }

}

void get_hash(void* hash_ctx,char* out_buf)
{
    if(chosen_has_algo == SHA_256)
    {
        SHA256_End((SHA256_CTX*)hash_ctx, out_buf);
    }
    else if(chosen_has_algo == BLAKE_2B)
    {
        blake2b_final(hash_ctx, out_buf);
    }
    else if(chosen_has_algo == BLAKE_2S)
    {
        blake2s_final(hash_ctx, out_buf);
    }
    free(hash_ctx);
}

char* H(char* in_buf,char* out_buf, unsigned int len)
{
    if(chosen_has_algo == SHA_256)
    {
        SHA256_CTX*	ctx256 = (SHA256_CTX*)malloc(sizeof(SHA256_CTX));
        SHA256_Init(ctx256);
        SHA256_Update(ctx256, (unsigned char*)in_buf, len);
        SHA256_End(ctx256,out_buf);
        free(ctx256);
    }
    else if(chosen_has_algo == BLAKE_2B)
    {
        blake2b(out_buf, N, NULL, 0, in_buf, len);
    }
    else if(chosen_has_algo == BLAKE_2S)
    {
        blake2s(out_buf, N, NULL, 0, in_buf, len);
    }
    return out_buf;
}

int hex_to_int(char c)
{
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}

int hex_to_ascii(char c, char d)
{
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}

void substr(char dest[], char src[], int offset, int len)
{
    int i;
    for(i = 0; i < len && src[offset + i] != '\0'; i++)
	    dest[i] = src[i + offset];
    dest[i] = '\0';
}

void to_ascii(char* dest, char *text)
{
  unsigned int i = 0;
  for(i = 0 ; i<strlen(text); i=i+2)
  {
    char chunk[3];
    substr(chunk,text, i,2);
    //printf("\n [%d] :%s \n ",i,chunk);
    char chuck_conv[2];
    chuck_conv[0] =  hex_to_ascii(chunk[0],chunk[1]);
    //sprintf (chuck_conv, "&#37;c", strtoul(chunk, NULL, 16));
     memcpy(dest + (i/2), &chuck_conv[0], sizeof(char));
  }
}

void strip(char *s) 
{
    char *p2 = s;
    while(*s != '\0') {
    	if(*s != '\t' && *s != '\n') {
    		*p2++ = *s++;
    	} else {
    		++s;
    	}
    }
    *p2 = '\0';
}

void print_buffer(char* print,unsigned int len)
{
    int i = 0;
    for( i = 0; i< len;i++)
    {
        printf("%c",print[i]);
    }
    printf("\n ");
}

unsigned int power(unsigned int x, unsigned int y)
{
    unsigned int i = 0;
    unsigned int sum = x;

    for(i = 1; i < y;i++)
    {
        sum = sum * x;
    }
    return sum;
}

unsigned int compare(char* src, char* dst, int len)
{
    unsigned int i = 0;  
    for( i = 0; i < len; i++)
    {
        if(src[i] == dst[i])
        {
            continue;
        }
        else
        {
            return 0;
        }
    }
    return 1;
}

void cleanup_link_list(list_node_t*  root)
{
    list_node_t*  curr_node = root; 
    list_node_t*  temp_node = root; 

    while(curr_node != NULL)
    {
        temp_node = curr_node->next;
        if(curr_node->data != NULL)
            free(curr_node->data);
        if(curr_node != NULL)
            free(curr_node);
        curr_node = temp_node;
    }
}

