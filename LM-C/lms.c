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
    char      temp_string[4] = {0};
    
    entropy_read(lms_private_key->I,31);
    lms_private_key->priv  = (list_node_t *) malloc(NUM_LEAF_NODES *sizeof(list_node_t));
    lms_private_key->pub   = (list_node_t *) malloc(NUM_LEAF_NODES *sizeof(list_node_t));
    for(q = 0; q < NUM_LEAF_NODES; q++)
    {
        lms_private_key->priv[(unsigned int)q].data = (void *)generate_private_key();
        lms_private_key->pub[(unsigned int)q].data  = (void *)generate_public_key(
                                                        (list_node_t* )lms_private_key->priv[(unsigned int)q].data,\
                                                        lms_private_key->I, uint32ToString(q,temp_string));
        printf(" Generating %u th OTS key PUBLIC KEY %s \n",q,stringToHex(lms_private_key->pub[(unsigned int)q].data,N));
    }
    
    lms_private_key->nodes  = (list_node_t *) malloc( 2* NUM_LEAF_NODES *sizeof(list_node_t));
    for(q = 0; q < 2* NUM_LEAF_NODES; q++)
    {
        lms_private_key->nodes[(unsigned int)q].data = (char *)malloc(32 * sizeof(char));
    }
    lms_private_key->leaf_num = 0;
    lms_private_key->lms_public_key = T(lms_private_key,1);
    return lms_private_key;
}

char* T(lms_priv_key_t* private_key, unsigned int j)
{
        list_node_t* lm_ots_pub_key = NULL;
        unsigned int height_index = NUM_LEAF_NODES;
        char temp_input[1024] = {0};
        char temp_string[4] = {0};

        if (j >= height_index)
        {
            lm_ots_pub_key = (list_node_t*)&(private_key->pub[j - height_index]);
            memcpy(temp_input,lm_ots_pub_key->data,N);
            memcpy(temp_input + N,private_key->I,31);
            memcpy(temp_input + N + 31,uint32ToString(j,temp_string),4);
            memcpy(temp_input + N + 35,uint8ToString(D_LEAF,temp_string),1);
            H(temp_input,private_key->nodes[j].data,N +36);
            //printf("INPUT PUB: %s \n",stringToHex(lm_ots_pub_key->data,N));
            //printf("INPUT I: %s \n",stringToHex(private_key->I,31));
            //printf("INPUT j: %s \n",stringToHex(uint32ToString(j),4));
            //printf("INPUT D_LEAF: %s \n",stringToHex(uint8ToString(D_LEAF),1));
            //printf("INPUT %s \n",stringToHex(temp_input,N +36));
           
        }
        else
        {
            memcpy(temp_input, T(private_key,2*j),N*sizeof(char));
            memcpy(temp_input + N*sizeof(char), T(private_key,2*j + 1),N*sizeof(char));
            memcpy(temp_input + 2*N*sizeof(char), private_key->I ,31*sizeof(char));
            memcpy(temp_input + (2*N + 31)*sizeof(char), uint32ToString(j,temp_string),4*sizeof(char));
            memcpy(temp_input + (2*N + 35)*sizeof(char), uint8ToString(D_INTR,temp_string),1*sizeof(char));
            H(temp_input,private_key->nodes[j].data,2*N + 36);
            //printf("INPUT T(%d): %s \n",2*j,stringToHex(temp_input,N));
            //printf("INPUT T(%d): %s \n",2*j + 1,stringToHex(temp_input +N,N));
            //printf("INPUT I: %s \n",stringToHex(private_key->I,31));
            //printf("INPUT j: %s \n",stringToHex(uint32ToString(j),4));
            //printf("INPUT D_LEAF: %s \n",stringToHex(uint8ToString(D_INTR),1));
            //printf("INPUT %s \n",stringToHex(temp_input,2*N +36));
        }
        //printf("OUTPUT T(%d): %s \n",j,stringToHex(private_key->nodes[j].data,N));
        //exit(1);
        return private_key->nodes[j].data;
        
}

char* get_public_key(lms_priv_key_t* private_key)
{
    return private_key->lms_public_key;
}

char* lms_generate_signature(lms_priv_key_t* lms_private_key,char* message,unsigned int* sign_len)
{
    char* sig = NULL;
    list_node_t* path = NULL;
    unsigned int len_lm_ots_sig = 0;
    char temp_string[4] = {0};
    if (lms_private_key->leaf_num >= NUM_LEAF_NODES)
        return NULL;
   sig = lmots_generate_signature((list_node_t* )lms_private_key->priv[lms_private_key->leaf_num].data, 
                                    lms_private_key->I,
                                    uint32ToString(lms_private_key->leaf_num,temp_string),
                                    message,
                                    &len_lm_ots_sig);
    // C, I, q, y = decode_lmots_sig(sig)
    path = get_path(lms_private_key,lms_private_key->leaf_num);
    //leaf_num = self.leaf_num
    lms_private_key->leaf_num = lms_private_key->leaf_num + 1;
    return encode_lms_sig(sig,len_lm_ots_sig, path,sign_len);
}

list_node_t* get_path(lms_priv_key_t* lms_private_key, unsigned int leaf_num)
{
    unsigned int node_num = leaf_num + NUM_LEAF_NODES;
    //printf("signing node %d \n ",node_num);
    list_node_t* root_node = NULL;
    list_node_t* temp_node = NULL;
    list_node_t* curr_node = NULL;
     
    while(node_num > 1)
    {
        temp_node = (list_node_t*)malloc(sizeof(list_node_t));
        temp_node->data = (char*) malloc(32*sizeof(char));
        if (node_num % 2)
        {
            //printf("path %d: %s \n ", node_num - 1,stringToHex(lms_private_key->nodes[node_num - 1].data,N*sizeof(char)));
            //path.append(self.nodes[node_num - 1])
            memcpy(temp_node->data,lms_private_key->nodes[node_num - 1].data,N*sizeof(char));
        }
        else
        {
            //print "path " + str(node_num + 1) + ": " + stringToHex(self.nodes[node_num + 1])
            //printf("path %d: %s \n ", node_num + 1,stringToHex(lms_private_key->nodes[node_num + 1].data,N*sizeof(char)));
            memcpy(temp_node->data,lms_private_key->nodes[node_num + 1].data,N*sizeof(char));
        }
        
        node_num = node_num/2;
        if(root_node == NULL)
        {
            root_node = temp_node;
            curr_node = temp_node;
            continue;
        }
        curr_node->next = temp_node;
        curr_node = temp_node;
    }
    return root_node;
}

char* encode_lms_sig(char* sig, unsigned int lm_ots_len, list_node_t* path,unsigned int* lms_len)
{
    char* result = (char*) malloc( 2* 1024);
    unsigned int len = 0;
    char temp_string[4] = {0};    
    list_node_t*  temp_node = NULL;
    memcpy(result,uint32ToString(LMS_SHA256_N32_H10,temp_string),4*sizeof(char));
    len = 4*sizeof(char);
    memcpy(result +len,sig,lm_ots_len);
    len = len + lm_ots_len;
    temp_node = path;
    
    while(temp_node != NULL)
    {
        //printf(" %s \n",stringToHex(temp_node->data,N));
        memcpy(result + len,temp_node->data, N*sizeof(char));
        len = len + (N*sizeof(char));
        temp_node  = temp_node->next;
    }
    *lms_len = len;

    //printf("SIG: %s \n",stringToHex(result,len));
    
    return result;
}

void decode_lms_sig(char* sig,lms_sig_t* lms_signature,unsigned int len_sig)
{
    list_node_t*  temp_node = NULL;
    list_node_t*  curr_node = NULL;
    unsigned int  i         = 0;
    unsigned int  pos       = 0;
    memcpy(lms_signature->typecode,sig,4);

    //if (typecode != uint32ToString(lms_sha256_n32_h10)):
    //    print "error decoding signature; got typecode " + stringToHex(typecode) + ", expected: " + stringToHex(uint32ToString(lms_sha256_h10))
    //    return ""
    lms_signature->lm_ots_sig = (char *) malloc(bytes_in_lmots_sig());
    memcpy(lms_signature->lm_ots_sig, sig + 4*sizeof(char),bytes_in_lmots_sig());
    //printf("LM OTS SIGN : %s \n ",stringToHex(lms_signature->lm_ots_sig,bytes_in_lmots_sig()));
    pos = 4 + bytes_in_lmots_sig();    
    for(i = 0; i < HEIGHT; i++)
    {
        //print "sig[" + str(i) + "]:\t" + stringToHex(sig[pos:pos+n])
        temp_node = (list_node_t*)malloc(sizeof(list_node_t));
        temp_node->data =(char* ) malloc(32 *sizeof(char));
        memcpy(temp_node->data, sig + pos, N);
        pos = pos + N;
        if(curr_node == NULL)
        {
            curr_node = temp_node;
            lms_signature->path = temp_node;
            continue;
        }
        curr_node->next = temp_node;
        curr_node = temp_node;

    }

}

void print_lms_sig(char* sig, unsigned int len_sig)
{
    unsigned int i = 0;
    lms_sig_t lms_signature;
    list_node_t*  temp_node = NULL;    
    decode_lms_sig(sig, &lms_signature,len_sig);
    print_lmots_signature(lms_signature.lm_ots_sig);
    temp_node = lms_signature.path; 
    
    while(temp_node != NULL)
    {
        printf("path[%d]: \t %s \n ",i,stringToHex(temp_node->data,N));
        temp_node = temp_node->next;
        i++;
    }
}

unsigned int lms_verify_signature(char* sig, char* public_key, char* message, unsigned int len_sig)
{
    lms_sig_t lms_signature;
    lm_ots_sig_t decoded_sig;    
    unsigned int node_num = 0;
    list_node_t*  temp_node = NULL;        
    char temp_input[1024] = {0};
    char temp_string[4] = {0};    
    char temp[1024] = {0};
    decode_lms_sig(sig, &lms_signature,len_sig);
    temp_node = lms_signature.path;
    decode_lmots_sig(lms_signature.lm_ots_sig,&decoded_sig);// note: only q is actually needed here
    node_num = stringToUint(decoded_sig.q,4) + NUM_LEAF_NODES;
    
    char* tmp = lmots_sig_to_public_key(lms_signature.lm_ots_sig, message);
    memcpy(temp_input,tmp,N*sizeof(char));
    memcpy(temp_input + N*sizeof(char),decoded_sig.I,31*sizeof(char));
    memcpy(temp_input + (N + 31)*sizeof(char),uint32ToString(node_num,temp_string),4*sizeof(char));
    memcpy(temp_input + (N + 35)*sizeof(char),uint8ToString(D_LEAF,temp_string),1);

    H(temp_input,temp_input,N+36);
    memcpy(temp,temp_input,N);
    while(node_num > 1)
    {
        //printf("S(%d):\t %s \n ",node_num, stringToHex(temp_input,N));
        //printf("temp_node %p \n ",temp_node);
        //printf("data %s %d \n ",stringToHex(temp_node->data,N),node_num);
        if (node_num % 2)
        {
            //print "adding node " + str(node_num - 1)
            memcpy(temp,temp_node->data,N*sizeof(char));
            memcpy(temp + N ,temp_input,N*sizeof(char));
            memcpy(temp + 2*N,decoded_sig.I,31*sizeof(char));
            memcpy(temp +2*N + 31,uint32ToString(node_num/2,temp_string),4*sizeof(char));
            memcpy(temp +2*N + 35,uint8ToString(D_INTR,temp_string),1);
            //printf("INPUT: %s \n ",stringToHex(temp, 2*N +36));
            H(temp,temp_input, 2*N +36);
        }
        else
        {
            // print "adding node " + str(node_num + 1)
            memcpy(temp + N ,temp_node->data,N*sizeof(char));
            memcpy(temp + 2*N,decoded_sig.I,31*sizeof(char));
            memcpy(temp +2*N + 31,uint32ToString(node_num/2,temp_string),4*sizeof(char));
            memcpy(temp +2*N + 35,uint8ToString(D_INTR,temp_string),1);
            //printf("INPUT: %s \n ",stringToHex(temp, 2*N +36));
            H(temp,temp_input, 2*N +36);
        }
        memcpy(temp,temp_input,N);
        node_num = node_num/2;
        temp_node = temp_node->next;
    }
    
    //print "pubkey: " + stringToHex(tmp)
    if (compare(temp,public_key,N))
    {
        return 1;
    }
    else
    {
        return 0;
     }
}
