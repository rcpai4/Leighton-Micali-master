#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

//User defined headers
#include "commons.h"
#include "lm_ots.h"

list_node_t* generate_private_key(void)
{
    int i = 0;
    list_node_t* root     =  NULL;
    list_node_t* temp_node = NULL;
    list_node_t* curr_node = root;
    
    for(i = 0; i < P; i++)
    {
        temp_node = (list_node_t*)malloc(sizeof(list_node_t));
        temp_node->data = malloc(N * sizeof(char));
        entropy_read(temp_node->data,N);
        if(curr_node == NULL)
        {
            curr_node   = temp_node;
            root        = temp_node;
            continue;
        }
        curr_node->next = temp_node;
        curr_node = temp_node;
    }
    return root;
}

char* generate_public_key(list_node_t* private_key, char* I, char* q)
{    
    void* hash_handle = hash_create();
    unsigned int i = 0, j = 0;
    char* public_key = (char* )malloc(N * sizeof(char));
    hash_update(hash_handle,I,31);
    hash_update(hash_handle,q,4);
    list_node_t* temp_node =  private_key;
    while(temp_node != NULL)
    {
        char *tmp = temp_node->data;
        //TODO: change this code
        char temp_text[1024] ={'\0'};
        char hash_text[N + 1] ={'\0'};
        //print "i:" + str(i) + " range: " + str(range(0, 256))
        memcpy(temp_text,tmp,32* sizeof(char));
        for(j = 0; j < 256;j++)
        {
            memcpy(temp_text + ( 32 * sizeof(char)), I,31 * sizeof(char));
            memcpy(temp_text + ( 63 * sizeof(char)), q,4*sizeof(char));
            memcpy(temp_text + ( 67 * sizeof(char)), uint16ToString(i),2);
            memcpy(temp_text + ( 69 * sizeof(char)), uint8ToString(j),1);
            memcpy(temp_text + ( 70 * sizeof(char)), uint8ToString(0),1);
            if(0)
            {
                printf("tmp: %s \n ",stringToHex(tmp,32));
                printf("I: %s \n ",stringToHex(I,31));
                printf("q: %s \n ",stringToHex(q,4));      
                printf("i: %d \n ",i);            
                printf("i: %s \n ",uint16ToString((unsigned short int )i));            
                printf("i: %s \n ",stringToHex(uint16ToString((unsigned short int )i),2));            
                printf("j: %s \n ",stringToHex(uint8ToString(j),1));            
                printf("D_ITER: %s \n ",stringToHex(uint8ToString(0),1));
                printf("input: %s \n ",stringToHex(temp_text,71));
            }
            H(temp_text,hash_text,71);
            memcpy(temp_text,hash_text,32);
            if(0)
            {
                printf("i: %d - %s \n ",i,stringToHex(temp_text,32));
                exit(1);
            }
            temp_text[32] = '\0';
        }
        //printf("i: %d - %s \n ",i,stringToHex(temp_text,32));
        hash_update(hash_handle,temp_text,32 * sizeof(char));
        temp_node = temp_node->next;
        i++;
    }
    
    //printf("\n WOW: %s \n",stringToHex(&vis,1));
    hash_update(hash_handle,uint8ToString(01),1);
    get_hash(hash_handle,public_key);
    //printf("PUBLIC Key: %s \n ",stringToHex(lm_ots_handle->public_key->data,32));
    return public_key;
}

char* lmots_generate_signature(list_node_t* lm_ots_private_key, char* I,char* q, char* message, char* entropy_message)
{
    char *C = (char *) malloc(sizeof(char) * N);
    char *temp_hash_output = (char *) malloc(sizeof(char) * (2*N + 1));
    void* hash_handle = hash_create();
    int i = 0, j = 0;
    entropy_read(C,N);
#if FILE_READ 
    // Overwrite the random array
    memcpy(C,entropy_message,N);
#endif
    //printf(" C: %s \n",stringToHex(C,32));
    char temp_hashQ[1024];
    memcpy(temp_hashQ,message, strlen(message));
    memcpy(temp_hashQ + strlen(message),C, 32);
    memcpy(temp_hashQ + strlen(message) + 32,I, 31);
    memcpy(temp_hashQ + strlen(message) + 63 ,q, 4);
    memcpy(temp_hashQ + strlen(message) + 67, uint8ToString(D_MESG), 1);
    //printf(" inp hashQ: %s \n",stringToHex(temp_hashQ,68 + strlen(message)));
    hash_update(hash_handle,message, strlen(message));
    hash_update(hash_handle,C, N*sizeof(char));
    hash_update(hash_handle,I, 31 * sizeof(char));
    hash_update(hash_handle,q, 4 * sizeof(char));
    hash_update(hash_handle,uint8ToString(D_MESG), 1);
    get_hash(hash_handle,temp_hash_output);
    //printf(" hashQ: %s \n",stringToHex(temp_hash_output,32));
    memcpy(temp_hash_output + 32 * sizeof(char),(void *)checksum(temp_hash_output,32),2 *sizeof(char));
    //printf("V: %s \n ",stringToHex(temp_hash_output ,34));
    list_node_t* root     =  NULL;
    list_node_t* temp_node = NULL;
    list_node_t* curr_node = root;
    list_node_t* curr_priv_key_node = lm_ots_private_key;
    char temp_input[1024];
    i = 0;
    while(curr_priv_key_node != NULL)
    {
        temp_node = (list_node_t*)malloc(sizeof(list_node_t));
        temp_node->data = malloc(N * sizeof(char));
        memcpy(temp_input,curr_priv_key_node->data, N);
        //printf("V[%d]: %u \n ",i,(unsigned char)(temp_hash_output[i]));    
        for (j = 0; j <  (unsigned char)(temp_hash_output[i]); j++)
        {
            memcpy(temp_input + N,I, 31);
            memcpy(temp_input + N + 31,q, 4);
            memcpy(temp_input + N + 35,uint16ToString(i), 2);
            memcpy(temp_input + N + 37,uint8ToString(j), 1);
            memcpy(temp_input + N + 38,uint8ToString(D_ITER), 1);
            //printf(" INPUT : %s \n ",stringToHex(temp_input ,N + 39));
            H(temp_input,temp_input, N+39);
            //printf(" OUTPUT : %s \n ",stringToHex(temp_node->data ,N));
        }
        memcpy(temp_node->data,temp_input,32);
        printf("%d [%s] \n ",i,stringToHex(temp_node->data,32));
        i++;
        curr_priv_key_node = curr_priv_key_node->next;
        if(curr_node == NULL)
        {
            curr_node   = temp_node;
            root        = temp_node;
            continue;
        }
        curr_node->next = temp_node;
        curr_node = temp_node;
    }
    return encode_lmots_signature(C, I, q, root);    
}


char* checksum(unsigned char *x, unsigned int len)
{
    char c1 = 0,c2 = 0;
    char* result =(char*) malloc(3 * sizeof(char));    
    unsigned int sum = 0;
    int i   = 0;
    for( i = 0 ; i < len ;i++)
    {
        sum = sum + (unsigned int)x[i];
        //printf(" checksum x[%d] %d sum: %u \n ",i,(int)x[i],sum);
    }    
    //printf(" checksum sum: %d \n ",sum);
    c2 = (char)(sum & 0xff);
    sum  = sum  >> 8;
    c1 = (char)(sum & 0xff);
    memcpy(result,&c1,1);
    memcpy(result + 1,&c2,1);
    return result;
}

char* encode_lmots_signature(char* C, char* I, char* q,list_node_t*  y)
{
    char* result = (char*)malloc(2*1024* sizeof(char));
    int len = 0;
    list_node_t*  temp_node;
    memcpy(result,uint32ToString(LMOTS_SHA256_N32_W8),4*sizeof(char));
    memcpy(result + (4 * sizeof(char)), C, N*sizeof(char));
    memcpy(result + ((4 + N) * sizeof(char)), I, 31*sizeof(char));
    memcpy(result + ((35 + N) * sizeof(char)),uint8ToString(0), 1*sizeof(char));    
    memcpy(result + ((36 + N) * sizeof(char)),q, 4*sizeof(char));    
    len = 40 + N;
    temp_node = y; 
    while(temp_node != NULL)
    {
        //printf(" %s \n",stringToHex(temp_node->data,N));
        memcpy(result + len,temp_node->data, N*sizeof(char));
        len = len + (N*sizeof(char));
        temp_node  = temp_node->next;
    }
    //printf("signture: %s \n ", stringToHex(result,len));
    return result;
}

void print_lmots_signature(char* lmots_signature)
{
    lm_ots_sig_t decoded_sig;
    list_node_t*  temp_node;
    unsigned int  i = 0;         
    decode_lmots_sig(lmots_signature,&decoded_sig);
    printf("C:\t %s\n",stringToHex(decoded_sig.C,N));
    printf("I:\t %s\n",stringToHex(decoded_sig.I,31));
    printf("q:\t %s\n",stringToHex(decoded_sig.q,4));
    temp_node = decoded_sig.y;
    while(temp_node != NULL)
    {
        printf("[%d] %s \n",i,stringToHex(temp_node->data,N));
        temp_node = temp_node->next;
        i++;
    }
}

void decode_lmots_sig(char *sig, lm_ots_sig_t* decoded_sig)
{
    char typecode[4] ={0};
    list_node_t* temp_node = NULL;
    list_node_t* curr_node = NULL;
    unsigned int i = 0; 
    memcpy(typecode,sig,4*sizeof(char));
    memcpy(decoded_sig->C,sig + 4*sizeof(char),N);
    memcpy(decoded_sig->I,sig + (N + 4)*sizeof(char),31);
    memcpy(decoded_sig->q,sig + (N + 36)*sizeof(char),4);
    unsigned int pos = N+40;
    
    for(i = 0; i < P; i++)
    {
        temp_node = (list_node_t*)malloc(sizeof(list_node_t));
        temp_node->data = malloc(N * sizeof(char));
        memcpy(temp_node->data,sig + pos,N);
        pos = pos + N;
        if(curr_node == NULL)
        {
            curr_node   = temp_node;
            decoded_sig->y = temp_node;
            continue;
        }
        curr_node->next = temp_node;
        curr_node = temp_node;
    }
}
unsigned int bytes_in_lmots_sig(void)
{
    return (N*(P+1)+40);// # 4 + n + 31 + 1 + 4 + n*p
}

unsigned int  lmots_verify_signature(char* public_key,char * sig, char* message)
{
    char* z = lmots_sig_to_public_key(sig, message);
    
    if(compare(public_key,z,N))
        return 1;
    else
        return 0;
}

char* lmots_sig_to_public_key(char *sig, char* message)
{
    lm_ots_sig_t decoded_sig;
    char* temp_hashQ = (char *) malloc(strlen(message) + 31 + 32 + 4 + 1);
    char* hashQ = (char *) malloc(33);
    char* temp_input = (char *) malloc(1024);
    char* public_key =(char*) malloc(N * sizeof(char));    
    void* hash_handle = hash_create();
    list_node_t* temp_node = NULL;
    int i = 0;
    unsigned int j = 0; 
    decode_lmots_sig(sig,&decoded_sig);
    memcpy(temp_hashQ,message, strlen(message));
    memcpy(temp_hashQ + strlen(message),decoded_sig.C, 32);
    memcpy(temp_hashQ + strlen(message) + 32,decoded_sig.I, 31);
    memcpy(temp_hashQ + strlen(message) + 63 ,decoded_sig.q, 4);
    memcpy(temp_hashQ + strlen(message) + 67, uint8ToString(D_MESG), 1);    
    H(temp_hashQ,hashQ,strlen(message) + 68);
    memcpy(temp_hashQ,hashQ,32);
    memcpy(temp_hashQ +32, checksum(hashQ,32), 2*sizeof(char));
    //printf( "V: %s \n",stringToHex(temp_hashQ,34));
    
    hash_update(hash_handle,decoded_sig.I,31);
    hash_update(hash_handle,decoded_sig.q,4);
    
    temp_node = decoded_sig.y;
    while(temp_node != NULL)
    {
        //printf("[%d] %s \n\n ",i,stringToHex(temp_node->data,N));
        memcpy(temp_input,temp_node->data,32);
        for (j = (unsigned char)(temp_hashQ[i]); j < 256; j++)
        {
            memcpy(temp_input + N,decoded_sig.I, 31);
            memcpy(temp_input + N + 31,decoded_sig.q, 4);
            memcpy(temp_input + N + 35,uint16ToString(i), 2);
            memcpy(temp_input + N + 37,uint8ToString(j), 1);
            memcpy(temp_input + N + 38,uint8ToString(D_ITER), 1);
            //printf(" INPUT[%d] : %s \n ",j,stringToHex(temp_input ,N + 39));
            H(temp_input,temp_input, N+39);
            //printf(" OUTPUT : %s \n ",stringToHex(temp_input,N));
            //exit(1);
        }
        hash_update(hash_handle,temp_input,32);
        temp_node = temp_node->next;
        i++;
    }
    hash_update(hash_handle,uint8ToString(D_PBLC),1);
    
    get_hash(hash_handle,public_key);
    return public_key;
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
    
    if(i == len)
    {
        return 1;
    }
}
