#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// User defined headers
#include "commons.h"
#include "lm_ots.h"

int lm_ots_test_case(void)
{
    random_handle_t* entropy_hdl = NULL;
    lm_ots_t* lm_ots_hdl = NULL;
    list_node_t* lm_ots_private_key = NULL;
    list_node_t* lm_ots_public_key = NULL;
    char* lm_ots_signature = NULL;
    list_node_t* temp_node = NULL;
    char* I = (char* )malloc(31 * sizeof(char));
    char* q = (char* )malloc(4 * sizeof(char));
    char* message = (char* )malloc(1024 * sizeof(char));
    unsigned int   i = 0;
    char* entropy_message = NULL; 
    
    entropy_hdl = entropy_create();
#if FILE_READ
    FILE *fp = NULL;
    fp = fopen("inputfile","r");
    char file_buff[1024]; 
#endif
    memcpy(I,entropy_read(entropy_hdl,31), 31 * sizeof(char));
#if FILE_READ
    fgets(file_buff,sizeof file_buff,fp);
    strip(file_buff);
    to_ascii(I,file_buff);
#endif
    memcpy(q,uint32ToString(0),4*sizeof(unsigned char));
#if FILE_READ    
    fgets(file_buff,sizeof file_buff,fp);
#endif
    lm_ots_hdl = create_lm_ots((void*)entropy_hdl);
    lm_ots_private_key = generate_private_key(lm_ots_hdl);
    temp_node = lm_ots_private_key; 

    while(temp_node != NULL)
    {
#if FILE_READ
    fgets(file_buff,sizeof file_buff,fp);
    strip(file_buff);
    to_ascii(temp_node->data,file_buff);
#endif        
        printf("PRIV KEY[%d]: %s \n",i,stringToHex(temp_node->data,N));
        temp_node = temp_node->next;
        i++;
    }
    lm_ots_public_key = generate_public_key(lm_ots_hdl,lm_ots_private_key, I,q);
    printf("\n PUB KEY : %s \n",stringToHex(lm_ots_public_key->data,32));
    
    strcpy(message,"The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no warrants shall issue, but upon probable cause, supported by oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized.");

    printf("message: %s\n", message);
#if FILE_READ
    entropy_message = (char *) malloc( 1024 * sizeof(char));   
    fgets(file_buff,sizeof file_buff,fp);
    strip(file_buff);
    to_ascii(entropy_message,file_buff);
#endif            
    lm_ots_signature = lmots_generate_signature(lm_ots_hdl,lm_ots_private_key, I, q, message,entropy_message);
    
    print_lmots_signature(lm_ots_signature);
    
    printf("verification: \n");
    printf( "true positive test: \n");
    if(lmots_verify_signature(lm_ots_hdl,lm_ots_public_key,lm_ots_signature,message))
    {
        printf("passed: message/signature pair is valid as expected \n");
    }
    else
    {
        printf("failed: message/signature pair is invalid \n ");
    }
    
    if(lmots_verify_signature(lm_ots_hdl,lm_ots_public_key,lm_ots_signature,message))
    {
        printf("failed: message/signature pair is valid (expected failure) \n");
    }
    else
    {
        printf("passed: message/signature pair is invalid as expected \n");
    }

    return 0;
}

int main(int charc, char ** charv)
{
    printf("Hello World of cryptography ECE 5580!!! \n ");
    return 0;
}

