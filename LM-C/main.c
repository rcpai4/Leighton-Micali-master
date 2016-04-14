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
    list_node_t*    lm_ots_private_key  = NULL;
    char*           lm_ots_public_key   = NULL;
    char*           lm_ots_signature    = NULL;
    list_node_t*    temp_node           = NULL;
    char*           I                   = (char* )malloc(ENTROPY_SIZE * sizeof(char));
    char*           q                   = (char* )malloc(4 * sizeof(char));
    char*           message             = (char* )malloc(MSG_SIZE * sizeof(char));
    unsigned int    i                   = 0;
    char            temp_string[5]      = {0};
    unsigned int    lm_ots_len          = 0;     
    printf(" LM-OTS TEST CASE \n ");    
    /* Create Random number Generator */
    entropy_create();
    entropy_read(I,ENTROPY_SIZE);
    memcpy(q,uint32ToString(0,temp_string),4*sizeof(unsigned char));
    /* Generate Private Key */
    lm_ots_private_key  = generate_private_key();
    temp_node           = lm_ots_private_key; 
    while(temp_node != NULL)
    {
        printf("PRIV KEY[%d]: %s \n",i,stringToHex(temp_node->data,N));
        temp_node = temp_node->next;
        i++;
    }
    
    /* Generate Public Key */
    lm_ots_public_key = generate_public_key(lm_ots_private_key, I,q);
    printf("\n PUB KEY : %s \n",stringToHex(lm_ots_public_key,32));
    strcpy(message,"The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no warrants shall issue, but upon probable cause, supported by oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized.");
    printf("message: %s\n", message);
    
    /* Generate Signature  */
    lm_ots_signature = lmots_generate_signature(lm_ots_private_key, I, q, message,&lm_ots_len);
    print_lmots_signature(lm_ots_signature);
    printf("Verification: \n");
    printf( "True positive test: \n");
    if(lmots_verify_signature(lm_ots_public_key,lm_ots_signature,message))
    {
        printf("Passed: message/signature pair is valid as expected \n");
    }
    else
    {
        printf("Failed: message/signature pair is invalid \n ");
    }
    if(lmots_verify_signature(lm_ots_public_key,lm_ots_signature,"other message"))
    {
        printf("Failed: message/signature pair is valid (expected failure) \n");
    }
    else
    {
        printf("Passed: message/signature pair is invalid as expected \n");
    }

    //lm_ots_cleanup_keys(lm_ots_private_key,lm_ots_public_key);
    //free(message);
    //free(q);
    //free(I);
   
    return 1;
}

int lms_test_case(void)
{
    lms_priv_key_t* lms_private_key     = NULL; 
    unsigned int    sign_len            = 0;
    char*           lms_public_key      = NULL;
    char*           message             = (char* )malloc(MSG_SIZE * sizeof(char));
    char*           sig                 = NULL;
    unsigned int    i                   = 0;
        
    printf("\n  LMS TEST CASE \n ");    
    NUM_LEAF_NODES = power(2,HEIGHT);    
   strcpy(message,"The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no warrants shall issue, but upon probable cause, supported by oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized.");
    printf("message: %s\n", message);    

    /* Create Random number Generator */    
    entropy_create();
    
    /* Generate Private Key */
    lms_private_key = create_lms_priv_key();
    
    /* Generate Public Key */
    lms_public_key = get_public_key(lms_private_key);
    printf(" LMS PUBLIC KEY: %s \n",stringToHex(lms_public_key,32));
    
    /* Generate Signature */    
    for(i = 0; i < NUM_LEAF_NODES ; i++)
    {
        printf("SIGNATURE %d \n",i);
        sig  = lms_generate_signature(lms_private_key,message,&sign_len);
        //printf("SIGNATURE %s \n",stringToHex(sig,sign_len));
        print_lms_sig(sig,sign_len);
        printf("True positive test \n");
        if (lms_verify_signature(sig,lms_public_key,message,sign_len) == 1)
        {
            printf("Passed: LMS message/signature pair is valid \n ");
        }
        else
        {
            printf("Failed: LMS message/signature pair is invalid \n ");
        }
    
        printf("False positive test \n ");
        if (lms_verify_signature(sig,lms_public_key,"other message",sign_len) == 1)
        {
            printf("Failed: LMS message/signature pair is valid (expected failure) \n ");
        }
        else
        {
            printf("Passed: LMS message/signature pair is invalid as expected \n ");
        }
    }
    return 1; 
}

void usage(char *prog, char *msg) {
	fprintf(stderr, "%s\nUsage:\t%s [options] \nOptions:\n\t-lmots\tRUN LMOTS TEST CASE\n\t-LMS\tGenerate LMS Testcase\n", msg, prog);
	exit(-1);
}

int main(int argc, char ** argv)
{
    printf("Hello to the World of cryptography ECE 5580!! \n ");
    unsigned int  ac = 1;
    char *av;
    unsigned int algo = 0;
    ac = 1;
	while (ac < argc) 
    {
		if (*argv[ac] == '-') 
        {
			av = argv[ac] + 1;
			if (!strcmp(av, "lmots")) {
				algo |= 1;
			} else if (!strcmp(av, "lms")) {
				algo |= 2;
			} else {
				usage(argv[0], "Invalid option.");
			}
			ac++;
		} else {
			if (ac != argc) {
				usage(argv[0], "Too many arguments.");
			}
		}
	}
    if (algo & 1)
    {
        lm_ots_test_case();
    }

    if (algo & 2)
    {
        lms_test_case();
    }
    return 0;
}

