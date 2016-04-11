#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

//User defined headers
#include "commons.h"
#include "lm_ots.h"
#include "lms.h"

lms_priv_key_t* create_lms_priv_key(void)
{
    lms_priv_key_t* lms_private_key = (lms_priv_key_t*) malloc(sizeof(lms_priv_key_t));    
    unsigned  int q = 0;
    
    entropy_read(lms_private_key->I,31);
    lms_private_key->priv  = (list_node_t *) malloc(((unsigned int )pow(2,HEIGHT)) *sizeof(list_node_t));
    lms_private_key->pub   = (list_node_t *) malloc(((unsigned int )pow(2,HEIGHT)) *sizeof(list_node_t));

    for(q = 0; q < (unsigned int)pow(2,HEIGHT); q++)
    {
        lms_private_key->priv[(unsigned int)q].data = (void *)generate_private_key();
        lms_private_key->pub[(unsigned int)q].data  = (void *)generate_public_key(
                                                        (list_node_t* )lms_private_key->priv[(unsigned int)q].data,\
                                                        lms_private_key->I, uint32ToString(q));
        printf(" Generating %u th OTS key PUBLIC KEY %s \n",q,stringToHex(lms_private_key->pub[(unsigned int)q].data,N));
    }

    lms_private_key->nodes  = (list_node_t *) malloc( 2* ((unsigned int )pow(2,HEIGHT)) *sizeof(list_node_t));
    for(q = 0; q < (unsigned int)2* pow(2,HEIGHT); q++)
    {
        lms_private_key->nodes[(unsigned int)q].data = (char *)malloc(32 * sizeof(char));
    }
    lms_private_key->leaf_num = 0;
    lms_private_key->lms_public_key = T(lms_private_key,1);
    return lms_private_key;
}

char* T(lms_priv_key_t* private_key, unsigned int j)
{
        // print "T(" + str(j) + ")"
        list_node_t* lm_ots_pub_key = NULL;
        unsigned int height_index = (unsigned int)pow(2,HEIGHT);
        char temp_input[1024] = {0};

        if (j >= height_index)
        {
            lm_ots_pub_key = (list_node_t*)&(private_key->pub[j - height_index]);
            memcpy(temp_input,lm_ots_pub_key->data,N);
            memcpy(temp_input + N,private_key->I,31);
            memcpy(temp_input + N + 31,uint32ToString(j),4);
            memcpy(temp_input + N + 35,uint8ToString(D_LEAF),1);
            H(temp_input,private_key->nodes[j].data,N +36);
            return private_key->nodes[j].data;
        }
        else
        {
            memcpy(temp_input, T(private_key,2*j),N*sizeof(char));
            memcpy(temp_input + N*sizeof(char), T(private_key,2*j + 1),N*sizeof(char));
            memcpy(temp_input + 2*N*sizeof(char), private_key->I ,31*sizeof(char));
            memcpy(temp_input + (2*N + 31)*sizeof(char), uint32ToString(j),4*sizeof(char));
            memcpy(temp_input + (2*N + 35)*sizeof(char), uint8ToString(D_LEAF),1*sizeof(char));
            H(temp_input,private_key->nodes[j].data,2*N + 36);
            return private_key->nodes[j].data;
        }
}

char* get_public_key(lms_priv_key_t* private_key)
{
    return private_key->lms_public_key;
}

