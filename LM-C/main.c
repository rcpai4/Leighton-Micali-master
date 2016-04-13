#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// User defined headers
#include "commons.h"
#include "lm_ots.h"
#include "lms.h"

int lms_test_case(void);
int lm_ots_test_case(void);


int lm_ots_test_case(void)
{
    list_node_t* lm_ots_private_key = NULL;
    char* lm_ots_public_key = NULL;
    char* lm_ots_signature = NULL;
    list_node_t* temp_node = NULL;
    char* I = (char* )malloc(31 * sizeof(char));
    char* q = (char* )malloc(4 * sizeof(char));
    char* message = (char* )malloc(1024 * sizeof(char));
    unsigned int   i = 0;
    entropy_create();
    
    entropy_read(I,31);
    memcpy(q,uint32ToString(0),4*sizeof(unsigned char));
    lm_ots_private_key = generate_private_key();
    temp_node = lm_ots_private_key; 

    while(temp_node != NULL)
    {
        printf("PRIV KEY[%d]: %s \n",i,stringToHex(temp_node->data,N));
        temp_node = temp_node->next;
        i++;
    }
    lm_ots_public_key = generate_public_key(lm_ots_private_key, I,q);
    printf("\n PUB KEY : %s \n",stringToHex(lm_ots_public_key,32));
    
    strcpy(message,"The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no warrants shall issue, but upon probable cause, supported by oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized.");

    printf("message: %s\n", message);
    unsigned int lm_ots_len = 0; 
    lm_ots_signature = lmots_generate_signature(lm_ots_private_key, I, q, message,&lm_ots_len);
    print_lmots_signature(lm_ots_signature);
    
    printf("verification: \n");
    printf( "true positive test: \n");
    if(lmots_verify_signature(lm_ots_public_key,lm_ots_signature,message))
    {
        printf("passed: message/signature pair is valid as expected \n");
    }
    else
    {
        printf("failed: message/signature pair is invalid \n ");
    }
    
    if(lmots_verify_signature(lm_ots_public_key,lm_ots_signature,message))
    {
        printf("failed: message/signature pair is valid (expected failure) \n");
    }
    else
    {
        printf("passed: message/signature pair is invalid as expected \n");
    }

    return 0;
}

int lms_test_case(void)
{
    printf(" LMS TEST CASE \n ");
    lms_priv_key_t* lms_private_key = NULL; 
    unsigned int sign_len = 0;
    char*           lms_public_key = NULL;
    list_node_t* temp_node = NULL;
    char* message = (char* )malloc(1024 * sizeof(char));
    char* sig = NULL;
    unsigned int i = 0;
   strcpy(message,"The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no warrants shall issue, but upon probable cause, supported by oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized.");
    printf("message: %s\n", message);    
    
    entropy_create();
    lms_private_key = create_lms_priv_key();
    lms_public_key = get_public_key(lms_private_key);
    printf(" LMS PUBLIC KEY: %s \n",stringToHex(lms_public_key,32));
    
    
    for(i = 0; i < (unsigned int) pow(2,HEIGHT); i++)
    {
        sig  = lms_generate_signature(lms_private_key,message,&sign_len);
        //printf("SIGNATURE %s \n",stringToHex(sig,sign_len));
        print_lms_sig(sig,sign_len);

        printf("SIGNATURE %d \n",i);
        printf("True positive test \n");
        if (lms_verify_signature(sig,lms_public_key,message,sign_len) == 1)
        {
            printf("passed: LMS message/signature pair is valid \n ");
        }
        else
        {
            printf("failed: LMS message/signature pair is invalid \n ");
        }
    
        printf("False positive test \n ");
        if (lms_verify_signature(sig,lms_public_key,"other message",sign_len) == 1)
        {
            printf("failed: LMS message/signature pair is valid (expected failure) \n ");
        }
        else
        {
            printf("passed: LMS message/signature pair is invalid as expected \n ");
        }
    }

    return 1; 
}

int main(int charc, char ** charv)
{
    printf("Hello World of cryptography ECE 5580!! \n ");
    //lm_ots_test_case();
    lms_test_case();
    return 0;
}

