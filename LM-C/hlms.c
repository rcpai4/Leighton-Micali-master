#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

//User defined headers
#include "commons.h"
#include "lm_ots.h"
#include "lms.h"
#include "hlms.h"


hlms_priv_key_t* create_hlms_priv_key(void)
{
    char*        lms_public_key_2 = NULL; 
    DEBUG_PRINT;
    hlms_priv_key_t* hlms_priv = (hlms_priv_key_t*) malloc(sizeof(hlms_priv_key_t));
    DEBUG_PRINT;
    /* Init Level 1*/
    hlms_priv->lms_priv_key_1 = create_lms_priv_key();
    DEBUG_PRINT;
    /* Init Level 2 */
    hlms_priv->lms_priv_key_2 = create_lms_priv_key();
    DEBUG_PRINT;
    
    lms_public_key_2 = get_public_key(hlms_priv->lms_priv_key_2);
    DEBUG_PRINT;    
    //printf("INPUT TO SIG1 : \n");
    hlms_priv->lms_sig_1      = lms_generate_signature(hlms_priv->lms_priv_key_1,lms_public_key_2,N);
    //printf("SIG1 %s \n ",stringToHex(hlms_priv->lms_sig_1,bytes_in_lms_sig()));
    //exit(1);
    return hlms_priv;
}

char* hlms_get_public_key(hlms_priv_key_t* hlms_private_key)
{
    return get_public_key(hlms_private_key->lms_priv_key_1);
}

char* hlms_generate_signature(hlms_priv_key_t* hlms_private_key,char *message,unsigned int mes_len)
{
    char* lms_sig = NULL;
    lms_sig  = lms_generate_signature(hlms_private_key->lms_priv_key_2,message,mes_len);
    
    if (lms_sig == NULL)
    {
        printf("Refreshing level 2 public/private key pair");
        hlms_init_level_2(hlms_private_key);
        lms_sig  = lms_generate_signature(hlms_private_key->lms_priv_key_2,message,mes_len);
        
    }
    return encode_hlms_sig(get_public_key(hlms_private_key->lms_priv_key_2), hlms_private_key->lms_sig_1, lms_sig);   
}

void hlms_init_level_2(hlms_priv_key_t *hlms_private_key)
{
    char*        lms_public_key_2 = NULL; 
    /*TODO: Clean up the earlier keys */
    hlms_private_key->lms_priv_key_2 = create_lms_priv_key();
    //self.sig1 = self.prv1.sign(self.prv2.get_public_key())
    lms_public_key_2 = get_public_key(hlms_private_key->lms_priv_key_2);        
    hlms_private_key->lms_sig_1      = lms_generate_signature(hlms_private_key->lms_priv_key_1,lms_public_key_2,N);
}

char* encode_hlms_sig(char* pub2, char* sig1, char* lms_sig)
{
    unsigned int len_lms_sig =  bytes_in_lms_sig();
    char* result = (char *) malloc(4 + N + len_lms_sig + len_lms_sig);
    uint32ToString(LMS_SHA256_N32_H10,result);
    memcpy(result + 4,pub2,N*sizeof(char));
    memcpy(result + 4 + N,sig1,len_lms_sig);
    memcpy(result + 4 + N + len_lms_sig ,lms_sig,len_lms_sig);
    return result;
}

void print_hlms_sig(char* sig)
{
    hlms_sig_t decoded_hlms_signature;
    decode_hlms_sig(sig,&decoded_hlms_signature);
    printf("pub2:\t %s  \n",stringToHex(decoded_hlms_signature.pub2,N));
    printf("sig1: \n");
    print_lms_sig(decoded_hlms_signature.sig1);
    printf("sig2: \n");
    print_lms_sig(decoded_hlms_signature.lms_sig);
}


void decode_hlms_sig(char* sig,hlms_sig_t* hlms_signature)
{
    unsigned int len_lms_sig =  bytes_in_lms_sig();
    memcpy(hlms_signature->typecode,sig,4);
    hlms_signature->pub2 = (char*) malloc(N);
    hlms_signature->sig1 = (char*) malloc(len_lms_sig);
    hlms_signature->lms_sig = (char*) malloc(len_lms_sig);
    //if (typecode != uint32ToString(hlms_sha256_n32_l2)):
    //    print "error decoding signature; got typecode " + stringToHex(typecode) + ", expected: " + stringToHex(uint32ToString(hlms_sha256_n32_l2))
     //   return ""
    memcpy(hlms_signature->pub2, sig + 4,N);
    memcpy(hlms_signature->sig1, sig + 4 + N,len_lms_sig);
    memcpy(hlms_signature->lms_sig, sig + 4 + N + len_lms_sig,len_lms_sig);
}

unsigned int hlms_verify_signature(char* sig, char* public_key, char* message, unsigned int mes_len)
{
    hlms_sig_t decoded_hlms_signature;
    //DEBUG_PRINT;
    decode_hlms_sig(sig,&decoded_hlms_signature);
    //DEBUG_PRINT;
    //printf("PUB2: %s \n",stringToHex(decoded_hlms_signature.pub2,N));
    //printf("SIG1: %s \n",stringToHex(decoded_hlms_signature.sig1,bytes_in_lms_sig()));
    //printf("LMS SIG: %s \n",stringToHex(decoded_hlms_signature.lms_sig,bytes_in_lms_sig()));
    //printf("PUBLIC: %s \n",stringToHex(public_key,N));
    if(lms_verify_signature(decoded_hlms_signature.sig1,
                            public_key,
                            decoded_hlms_signature.pub2,
                            N) == 1)
    {
        if(lms_verify_signature(decoded_hlms_signature.lms_sig,
                    decoded_hlms_signature.pub2,
                    message,
                    mes_len) == 1)
        {
            //DEBUG_PRINT;
            return 1;
        }
        else
        {
            //DEBUG_PRINT;
            printf("pub2 verification of lms_sig did not pass\n");
            return 0;
        }
    }
    else
    {
        //DEBUG_PRINT;
        printf("pub1 verification of sig1 did not pass\n");
        return 0;    
    }
}
        

