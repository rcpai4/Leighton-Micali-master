#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

//For SHA 
#include <stdio.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "sha2.h"

//User defined headers
#include "commons.h"

#if FILE_READ
FILE *fp_file = NULL;
char file_buff[1024]; 
#endif

void entropy_create(void)
{
    srand(time(0));
#if FILE_READ
    fp_file = fopen("inputfile_lms","r");
#endif
}

char* entropy_read(char* buffer, unsigned int n)
{
#if FILE_READ
    fgets(file_buff,sizeof file_buff,fp_file);
    strip(file_buff);
    to_ascii(buffer,file_buff);
#else
    FILE *fp = NULL;
    fp = fopen("/dev/urandom", "r");
    fread(buffer, 1, n, fp);
    fclose(fp);
#endif    
    return buffer;
}


char* uint32ToString(unsigned int x)
{
    char* data = (char* )malloc(32 * sizeof(char));
    memset(data,0,32 * sizeof(unsigned char));
    char c1 = 0,c2 = 0,c3 = 0,c4 =0;
    c4 = (char)(x & 0xff);
    x = x >> 8;
    c3 = (char)(x & 0xff);
    x = x >> 8;
    c2 = (char)(x & 0xff);
    x = x >> 8;
    c1 = (char)(x & 0xff);
    memcpy(data,&c1,sizeof(char));
    memcpy(data + (1* sizeof(char)),&c2,sizeof(char));
    memcpy(data + (2 * sizeof(char)),&c3,sizeof(char));
    memcpy(data + (3 * sizeof(char)),&c4,sizeof(char));
    return data;
}

char* uint16ToString(unsigned short int x)
{
    char c1 = 0,c2 = 0;
    char* result =(char*) malloc(3 * sizeof(char));
    c2 = (char)(x & 0xff);
    x = x >> 8;
    c1 = (char)(x & 0xff);
    memcpy(result,&c1,1);
    memcpy(result + 1,&c2,1);
    return result;
}

char* uint16ToString_debug(unsigned short int x)
{
    char c1 = 0,c2 = 0;
    char* result =(char*) malloc(3 * sizeof(char));
    memset(result, 0, 3* sizeof(char));
    c2 = (char)(x & 0xff);
    printf("c2:  %d\n ",c2);
    x = x >> 8;
    c1 = (char)(x & 0xff);
    printf("c1: %d\n ",c1);
    memcpy(result,&c1,1);
    memcpy(result + 1,&c2,1);
    printf("res 0: %u\n ",result[0]);
    printf("res 1: %u\n ",result[1]);
    printf("res 2: %u\n ",result[2]);    
    return result;
}


char* uint8ToString(unsigned char x)
{
    char* c1 = (char*) malloc(sizeof(unsigned char));
    *c1 = (char)(x & 0xff);
    return c1;
}

unsigned int stringToUint(unsigned char* x)
{
    /*TODO: */
    return 0;
}


char* stringToHex(char* x, unsigned int len)
{     
    static const char* const lut = "0123456789ABCDEF";
    char* y = x;    
    size_t i = 0;
    char* output = (char*) malloc(2*len*sizeof(char)); 
    memset(output,0,sizeof(2*len*sizeof(char)) + 1);
	
	for(i=0; i<len; i++) {
        const unsigned char c = y[i];
		output[i*2] = lut[c >> 4];
        //printf("%s %d - temp: %c \n ",__FUNCTION__,__LINE__,output[i*2]);
		output[i*2+1] = lut[c & 0x0f]; //nibbleToChar(bytes[i] & 0x0f);
        //printf("%s %d - temp: %c \n ",__FUNCTION__,__LINE__,output[i*2 +1]);
	}
    //output[i] = '\0';
	return output;    
}

void* hash_create(void)
{
    SHA256_CTX*	ctx256 = (SHA256_CTX*)malloc(sizeof(SHA256_CTX));
    SHA256_Init(ctx256);
    return (void*)ctx256;
}

void hash_update(void* hash_ctx,char* in_buf, unsigned int len)
{
    SHA256_Update((SHA256_CTX*)hash_ctx, (unsigned char*)in_buf, len);
}

void get_hash(void* hash_ctx,char* out_buf)
{
   SHA256_End((SHA256_CTX*)hash_ctx, out_buf);
}

char* H(char* in_buf,char* out_buf, unsigned int len)
{
    	SHA256_CTX	ctx256;
        SHA256_Init(&ctx256);
        SHA256_Update(&ctx256, (unsigned char*)in_buf, len);
        SHA256_End(&ctx256,out_buf);
        //printf("out_buf: %s \n",out_buf);
        //printf("out_buf again:");
        //print_buffer(out_buf,64);
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

void to_ascii(unsigned char* dest, unsigned char *text)
{
  unsigned int i = 0;
  for(i = 0 ; i<strlen(text); i=i+2)
  {
    unsigned char chunk[3];
    substr(chunk,text, i,2);
    //printf("\n [%d] :%s \n ",i,chunk);
    unsigned char chuck_conv[2];
    chuck_conv[0] =  hex_to_ascii(chunk[0],chunk[1]);
    //sprintf (chuck_conv, "&#37;c", strtoul(chunk, NULL, 16));
     memcpy(dest + (i/2), &chuck_conv[0], sizeof(unsigned char));
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
