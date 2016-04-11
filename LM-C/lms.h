
#define HEIGHT 10

typedef struct lms_priv_key
{
    char I[31];
    list_node_t* priv;
    list_node_t* pub;
    double leaf_num;
    // Array of all the nodes
    list_node_t* nodes;
    char* lms_public_key; 

} lms_priv_key_t;

char* T(lms_priv_key_t* private_key, unsigned int j);
