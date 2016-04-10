#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int hex_to_int(char c){
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
  int i = 0;
  for(i; i<strlen(text); i=i+2)
  {
    unsigned char chunk[3];
    substr(chunk,text, i,2);
    unsigned char chuck_conv[2];
    chuck_conv[0] =  hex_to_ascii(chunk[0],chunk[1]);
    //sprintf (chuck_conv, "&#37;c", strtoul(chunk, NULL, 16));
    printf("[%d] :%s - %d \n ",i,chunk, chuck_conv[0]);
    //dest = strcat ( dest, chuck_conv );
    memcpy(dest + (i/2), &chuck_conv[0], sizeof(unsigned char));
    printf("output - dest[%d] : %d \n ",i/2, *( dest + i/2));
  }
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
		output[i*2+1] = lut[c & 0x0f]; //nibbleToChar(bytes[i] & 0x0f);
        //printf(" LOGS :%c: %c %c \n ",c,output[i*2],output[i*2 +1]);
	}
    //output[i] = '\0';  
    return output;
}


int main()
{
    char text[1024] = "CC1305E386BF9762D0095981F4D0CE15856DE8DBE6724A72AFF27C00C185C9";
    char dest[1024] = {'\0'};
    int i  = 0;
    printf("\n text: %s \n ",text);
    printf("\n dest: %s \n ",dest);
    to_ascii(dest,text);
    printf("\n Finally dest: \n ");
    for( i =0; i < 31; i++)
    {
        printf("%d : %d \n ",i,dest[i]);
    }
    printf("\n Normal Finally dest: %s \n ",stringToHex(dest,31));
}
