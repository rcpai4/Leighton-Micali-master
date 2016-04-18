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
        temp_node->next = NULL;
        temp_node->data = malloc(N * sizeof(char));
        entropy_read(temp_node->data,N);
        //printf("i: %s \n",stringToHex(temp_node->data,N));
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

void print_link_list(list_node_t* root,unsigned  int len)
{
    unsigned int i = 0;
    list_node_t* temp_node = root;
    while(temp_node != NULL)
    {
        printf("[%d]: \t %s\n",i,stringToHex(temp_node->data,len));
        temp_node = temp_node->next;
        i++;
    }
}

char* generate_public_key(list_node_t* private_key, char* I, char* q)
{    
    void* hash_handle = hash_create();
    unsigned int i = 0, j = 0;
    char* public_key = (char* )malloc(N * sizeof(char));
    char temp_string[5] = {0};
    list_node_t* temp_node =  private_key;    
    char* temp_text = (char *)malloc(MSG_SIZE* sizeof(char));
    
    hash_update(hash_handle,I,ENTROPY_SIZE);
    hash_update(hash_handle,q,4);

    while(temp_node != NULL)
    {
        memcpy(temp_text,temp_node->data,N * sizeof(char));
        for(j = 0; j < 256;j++)
        {
            memcpy(temp_text + (N),I,ENTROPY_SIZE * sizeof(char));
            memcpy(temp_text + ( N + ENTROPY_SIZE ), q,4*sizeof(char));
            memcpy(temp_text + ( N + ENTROPY_SIZE + 4), uint16ToString(i,temp_string),2);
            memcpy(temp_text + ( N + ENTROPY_SIZE + 4 + 2), uint8ToString(j,temp_string),1);
            memcpy(temp_text + ( N + ENTROPY_SIZE + 4 + 2 + 1), uint8ToString(0,temp_string),1);
            H(temp_text,temp_text,N + ENTROPY_SIZE + 4 + 2 + 1 + 1);
        }

        //printf("[%d]: %s \n ",i,stringToHex(temp_text,32));
        hash_update(hash_handle,temp_text, N);
        temp_node = temp_node->next;
        i++;
    }
    hash_update(hash_handle,uint8ToString(D_PBLC,temp_string),1);
    get_hash(hash_handle,public_key);
    free(temp_text);
    //printf("PUBLIC Key: %s \n ",stringToHex(public_key,32));
    //exit(1);
    return public_key;
}

char* lmots_generate_signature(list_node_t* lm_ots_private_key, char* I,char* q, char* message, unsigned int mes_len)
{
    char            C[N]                        = {0};
    char            temp_hash_output[2*N + 1]   = {0};
    void*           hash_handle                 = hash_create();
    int             i = 0, j = 0;
    char            temp_string[5]              = {0};
    list_node_t*    root                        = NULL;
    list_node_t*    temp_node                   = NULL;
    list_node_t*    curr_node                   = NULL;
    list_node_t*    curr_priv_key_node          = lm_ots_private_key;
    char            temp_input[N + ENTROPY_SIZE + 4 + 2 + 1 + 1] = {0};
    entropy_read(C,N);
    hash_update(hash_handle,message, mes_len);
    hash_update(hash_handle,C, N);
    hash_update(hash_handle,I, ENTROPY_SIZE);
    hash_update(hash_handle,q, 4);
    hash_update(hash_handle,uint8ToString(D_MESG,temp_string), 1);
    get_hash(hash_handle,temp_hash_output);
    memcpy(temp_hash_output + N,checksum((unsigned char*)temp_hash_output,N),2 *sizeof(char));
    //printf("HashQ: %s\n ",stringToHex(temp_hash_output,N + 2));
    while(curr_priv_key_node != NULL)
    {
        temp_node = (list_node_t*)malloc(sizeof(list_node_t));
        temp_node->next = NULL;
        temp_node->data = (char *)malloc(N * sizeof(char));
        memcpy(temp_input,curr_priv_key_node->data, N);
        for (j = 0; j <  (unsigned char)(temp_hash_output[i]); j++)
        {
            memcpy(temp_input + N,I, ENTROPY_SIZE);
            memcpy(temp_input + N + ENTROPY_SIZE,q, 4);
            memcpy(temp_input + N + ENTROPY_SIZE + 4,uint16ToString(i,temp_string), 2);
            memcpy(temp_input + N + ENTROPY_SIZE + 4 + 2,uint8ToString(j,temp_string), 1);
            memcpy(temp_input + N + ENTROPY_SIZE + 4 + 2 + 1,uint8ToString(D_ITER,temp_string), 1);
            H(temp_input,temp_input, N + ENTROPY_SIZE + 4 + 2 + 1 + 1);
            //printf(" OUTPUT : %s \n ",stringToHex(temp_node->data ,N));
        }
        memcpy(temp_node->data,temp_input,N);
        //printf("%d [%s] \n ",i,stringToHex(temp_node->data,32));
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
    char* result = (char*)malloc(bytes_in_lmots_sig());
    unsigned int len = 0;
    list_node_t*  temp_node = NULL;
    char temp_string[5] = {0};
    unsigned int i = 0;
    memcpy(result,uint32ToString(LMOTS_SHA256_N32_W8,temp_string),4*sizeof(char));
    memcpy(result + (4), C, N*sizeof(char));
    memcpy(result + ((4 + N) * sizeof(char)), I, ENTROPY_SIZE*sizeof(char));
    memcpy(result + ((4 + ENTROPY_SIZE + N) * sizeof(char)),uint8ToString(0,temp_string), 1*sizeof(char));    
    memcpy(result + ((1 + 4 + ENTROPY_SIZE + N) * sizeof(char)),q, 4*sizeof(char));    
    len =  4 + 1 + 4 + ENTROPY_SIZE + N;
    temp_node = y; 
    while(temp_node != NULL)
    {
        memcpy(result + len,temp_node->data, N*sizeof(char));
        len = len + (N*sizeof(char));
        temp_node  = temp_node->next;
        i++;
    }
    //temp_node = y; 
    
    //while(temp_node != NULL)
    //{
        //printf("DATA: %p \n ",temp_node->data);
        //printf("NODE: %p \n ",temp_node);
    //    list_node_t*  prev_node = temp_node->next;
   //     free(temp_node->data);
    //    free(temp_node);
    //    temp_node = prev_node;
    //}
    //
    lm_ots_cleanup_keys(y,NULL);

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
    printf("I:\t %s\n",stringToHex(decoded_sig.I,ENTROPY_SIZE));
    printf("q:\t %s\n",stringToHex(decoded_sig.q,4));
    temp_node = decoded_sig.y;
    while(temp_node != NULL)
    {
        printf("[%d] %s \n",i,stringToHex(temp_node->data,N));
        temp_node = temp_node->next;
        i++;
    }
    
    /* Cleanup the keys we created */
    lm_ots_cleanup_keys(decoded_sig.y,NULL);

}

void decode_lmots_sig(char *sig, lm_ots_sig_t* decoded_sig)
{
    char typecode[4] ={0};
    list_node_t* temp_node = NULL;
    list_node_t* curr_node = NULL;
    unsigned int i = 0; 
    memcpy(typecode,sig,4*sizeof(char));
    memcpy(decoded_sig->C,sig + 4*sizeof(char),N);
    memcpy(decoded_sig->I,sig + (N + 4)*sizeof(char),ENTROPY_SIZE);
    memcpy(decoded_sig->q,sig + (N + 36)*sizeof(char),4);
    unsigned int pos = N+40;
    
    for(i = 0; i < P; i++)
    {
        temp_node = (list_node_t*)malloc(sizeof(list_node_t));
        temp_node->data = malloc(N * sizeof(char));
        temp_node->next = NULL;
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
    return (N*(P+1)+ ENTROPY_SIZE + 9);// # 4 + n + ENTROPY_SIZE + 1 + 4 + n*p
}

unsigned int  lmots_verify_signature(char* public_key,char * sig, char* message,unsigned int mes_len)
{

    char* z = lmots_sig_to_public_key(sig, message,mes_len);
    
    if(compare(public_key,z,N))
    {
        free(z);
        return 1;
    }
    else
    {
        free(z);
        return 0;
    }
}

char* lmots_sig_to_public_key(char *sig, char* message,unsigned int mes_len)
{
    lm_ots_sig_t decoded_sig;
    char temp_input[N + ENTROPY_SIZE + 4 + 2 + 1 + 1] = {0};
    char* hashQ = (char *) malloc(mes_len + N + ENTROPY_SIZE + 4 + 1);
    char* public_key =(char*) malloc(N * sizeof(char));    
    void* hash_handle = hash_create();
    list_node_t* temp_node = NULL;
    int i = 0;
    unsigned int j = 0; 
    char temp_string[5] ={0};

    decode_lmots_sig(sig,&decoded_sig);
    memcpy(hashQ,message, mes_len);
    memcpy(hashQ + mes_len,decoded_sig.C, N);
    memcpy(hashQ + mes_len + N,decoded_sig.I, ENTROPY_SIZE);
    memcpy(hashQ + mes_len + N + ENTROPY_SIZE,decoded_sig.q, 4);
    memcpy(hashQ + mes_len + N + ENTROPY_SIZE + 4, uint8ToString(D_MESG,temp_string), 1);    
    H(hashQ,hashQ,mes_len + N + ENTROPY_SIZE + 4 + 1);
    //memcpy(hashQ,hashQ,32);
    memcpy(hashQ + N, checksum((unsigned char *)hashQ,N), 2*sizeof(char));
    //printf( "V: %s \n",stringToHex(temp_hashQ,34));
    
    hash_update(hash_handle,decoded_sig.I,ENTROPY_SIZE);
    hash_update(hash_handle,decoded_sig.q,4);
    
    temp_node = decoded_sig.y;
    while(temp_node != NULL)
    {
        //printf("[%d] %s \n\n ",i,stringToHex(temp_node->data,N));
        memcpy(temp_input,temp_node->data,N);
        for (j = (unsigned char)(hashQ[i]); j < 256; j++)
        {
            memcpy(temp_input + N,decoded_sig.I, ENTROPY_SIZE);
            memcpy(temp_input + N + ENTROPY_SIZE,decoded_sig.q, 4);
            memcpy(temp_input + N + ENTROPY_SIZE + 4,uint16ToString(i,temp_string), 2);
            memcpy(temp_input + N + ENTROPY_SIZE + 4 + 2,uint8ToString(j,temp_string), 1);
            memcpy(temp_input + N + ENTROPY_SIZE + 4 + 2 + 1,uint8ToString(D_ITER,temp_string), 1);
            //printf(" INPUT[%d] : %s \n ",j,stringToHex(temp_input ,N + 39));
            H(temp_input,temp_input, N + ENTROPY_SIZE + 4 + 2 + 1 + 1);
            //printf(" OUTPUT : %s \n ",stringToHex(temp_input,N));
        }
        hash_update(hash_handle,temp_input,N);
        temp_node = temp_node->next;
        i++;
    }
    hash_update(hash_handle,uint8ToString(D_PBLC,temp_string),1);
    
    get_hash(hash_handle,public_key);
    
    /* Cleanup the keys we created */
    lm_ots_cleanup_keys(decoded_sig.y,NULL);
    free(hashQ);
    return public_key;
}


void lm_ots_cleanup_keys(list_node_t*  priv_key, char* pub_key)
{
    list_node_t*  curr_node = priv_key; 
    list_node_t*  temp_node = priv_key; 

    while(curr_node != NULL)
    {
        temp_node = curr_node->next;
        if(curr_node->data != NULL)
            free(curr_node->data);
        if(curr_node != NULL)
            free(curr_node);
        curr_node = temp_node;
    }
    
    if(pub_key != NULL)
    {
        free(pub_key);
    }
}

