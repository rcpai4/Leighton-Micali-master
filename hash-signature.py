# example implementation for Leighton-Micali hash based signatures
# Internet draft
#
# Notes:
#
#     * only a limted set of parameters are supported; in particular,
#     * w=8 and n=32
#
#     * HLMS, LMS, and LM-OTS are all implemented
#
#     * uncommenting print statements may be useful for debugging, or
#       for understanding the mechanics of
#
# LMOTS constants
#
D_ITER = chr(0x00) # in the iterations of the LM-OTS algorithms
D_PBLC = chr(0x01) # when computing the hash of all of the iterates in the LM-OTS algorithm
D_MESG = chr(0x02) # when computing the hash of the message in the LMOTS algorithms
D_LEAF = chr(0x03) # when computing the hash of the leaf of an LMS tree
D_INTR = chr(0x04) # when computing the hash of an interior node of an LMS tree

NULL   = chr(0)    # used as padding for encoding

lmots_sha256_n32_w8 = 0x08000008 # typecode for LM-OTS with n=32, w=8
lms_sha256_n32_h10  = 0x02000002 # typecode for LMS with n=32, h=10
hlms_sha256_n32_l2  = 0x01000001 # typecode for two-level HLMS with n=32


# LMOTS parameters
#
n = 32; p = 34; w = 8; ls = 0

def bytes_in_lmots_sig():
    return n*(p+1)+40 # 4 + n + 31 + 1 + 4 + n*p

from Crypto.Hash import SHA256
from Crypto import Random

# SHA256 hash function
#
def H(x):
#    print "hash input: " + stringToHex(x)
    h = SHA256.new()
    h.update(x)
    return h.digest()[0:n]

def sha256_iter(x, num):
    tmp = x
    for j in range(0, num):
        tmp = H(tmp + I + q + uint16ToString(i) + uint8ToString(j) + D_ITER)

# entropy source
#
entropySource = Random.new()

# integer to string conversion
#
def uint32ToString(x):
    c4 = chr(x & 0xff)
    x = x >> 8
    c3 = chr(x & 0xff)
    x = x >> 8
    c2 = chr(x & 0xff)
    x = x >> 8
    c1 = chr(x & 0xff)
    return c1 + c2 + c3 + c4

def uint16ToString(x):
    c2 = chr(x & 0xff)
    x = x >> 8
    c1 = chr(x & 0xff)
    return c1 + c2

def uint8ToString(x):
    return chr(x)

def stringToUint(x):
    sum = 0
    for c in x:
        sum = sum * 256 + ord(c)
    return sum

# string-to-hex function needed for debugging
#
def stringToHex(x):
    return "".join("{:02x}".format(ord(c)) for c in x)

# LM-OTS functions
#
def encode_lmots_sig(C, I, q, y):
    result = uint32ToString(lmots_sha256_n32_w8) + C + I + NULL + q
    for i, e in enumerate(y):
        result = result + y[i]
    return result

def decode_lmots_sig(sig):
    if (len(sig) != bytes_in_lmots_sig()):
        print "error decoding signature; incorrect length (" + str(len(sig)) + " bytes)"
    typecode = sig[0:4]
    if (typecode != uint32ToString(lmots_sha256_n32_w8)):
        print "error decoding signature; got typecode " + stringToHex(typecode) + ", expected: " + stringToHex(uint32ToString(lmots_sha256_n32_w8))
        return ""
    C = sig[4:n+4]
    I = sig[n+4:n+35]
    q = sig[n+36:n+40] # note: skip over NULL
    y = list()
    pos = n+40
    for i in range(0, p):
        y.append(sig[pos:pos+n])
        pos = pos + n
    return C, I, q, y

def print_lmots_sig(sig):
    C, I, q, y = decode_lmots_sig(sig)
    print "C:\t" + stringToHex(C)
    print "I:\t" + stringToHex(I)
    print "q:\t" + stringToHex(q)
    for i, e in enumerate(y):
        print "y[" + str(i) + "]:\t" + stringToHex(e)

# Algorithm 0: Generating a Private Key
#
def lmots_gen_priv():
    priv = list()
    for i in range(0, p):
        priv.append(entropySource.read(n))
    return priv

# Algorithm 1: Generating a Public Key From a Private Key
#
def lmots_gen_pub(private_key, I, q):
    hash = SHA256.new()
    hash.update(I + q)
    for i, x in enumerate(private_key):
        tmp = x
        # print "i:" + str(i) + " range: " + str(range(0, 256))
        for j in range(0, 256):
            tmp = H(tmp + I + q + uint16ToString(i) + uint8ToString(j) + D_ITER)
        hash.update(tmp)
    hash.update(D_PBLC)
    return hash.digest()

# Algorithm 2: Merkle Checksum Calculation
#
def checksum(x):
    sum = 0
    for c in x:
        sum = sum + ord(c)
    # print format(sum, '04x')
    c1 = chr(sum >> 8)
    c2 = chr(sum & 0xff)
    return c1 + c2

# Algorithm 3: Generating a Signature From a Private Key and a Message
#
def lmots_gen_sig(private_key, I, q, message):
    C = entropySource.read(n)
    hashQ = H(message + C + I + q + D_MESG)
    V = hashQ + checksum(hashQ)
    # print "V: " + stringToHex(V)
    y = list()
    for i, x in enumerate(private_key):
        tmp = x
        # print "i:" + str(i) + " range: " + str(range(0, ord(V[i])))
        for j in range(0, ord(V[i])):
            tmp = H(tmp + I + q + uint16ToString(i) + uint8ToString(j) + D_ITER)
        y.append(tmp)
    return encode_lmots_sig(C, I, q, y)

def lmots_sig_to_pub(sig, message):
    C, I, q, y = decode_lmots_sig(sig)
    hashQ = H(message + C + I + q + D_MESG)
    V = hashQ + checksum(hashQ)
    # print "V: " + stringToHex(V)
    hash = SHA256.new()
    hash.update(I + q)
    for i, y in enumerate(y):
        tmp = y
        # print "i:" + str(i) + " range: " + str(range(ord(V[i]), 256))
        for j in range(ord(V[i]), 256):
            tmp = H(tmp + I + q + uint16ToString(i) + uint8ToString(j) + D_ITER)
        hash.update(tmp)
    hash.update(D_PBLC)
    return hash.digest()

# Algorithm 4: Verifying a Signature and Message Using a Public Key
#
def lmots_verify_sig(public_key, sig, message):
    z = lmots_sig_to_pub(sig, message)
    # print "z: " + stringToHex(z)
    if z == public_key:
        return 1
    else:
        return 0

# LM-OTS test functions
#
I = entropySource.read(31)
q = uint32ToString(0)
private_key = lmots_gen_priv()

print "LMOTS private key: "
for i, x in enumerate(private_key):
    print "x[" + str(i) + "]:\t" + stringToHex(x)
    
public_key = lmots_gen_pub(private_key, I, q)

print "LMOTS public key: "
print stringToHex(public_key)

message = "The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no warrants shall issue, but upon probable cause, supported by oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized."

print "message: " + message

sig = lmots_gen_sig(private_key, I, q, message)

print "LMOTS signature byte length: " + str(len(sig))

print "LMOTS signature: "
print_lmots_sig(sig)

print "verification: "
print "true positive test: "
if (lmots_verify_sig(public_key, sig, message) == 1):
    print "passed: message/signature pair is valid as expected"
else:
    print "failed: message/signature pair is invalid"

print "false positive test: "
if (lmots_verify_sig(public_key, sig, "some other message") == 1):
    print "failed: message/signature pair is valid (expected failure)"
else:
    print "passed: message/signature pair is invalid as expected"



# LMS N-time signatures functions
#
h = 10 # height (number of levels -1) of tree

def encode_lms_sig(lmots_sig, path):
    result = uint32ToString(lms_sha256_n32_h10) + lmots_sig
    for i, e in enumerate(path):
        result = result + path[i]
    return result

def decode_lms_sig(sig):
    typecode = sig[0:4]
    if (typecode != uint32ToString(lms_sha256_n32_h10)):
        print "error decoding signature; got typecode " + stringToHex(typecode) + ", expected: " + stringToHex(uint32ToString(lms_sha256_h10))
        return ""
    pos = 4 + bytes_in_lmots_sig()
    lmots_sig = sig[4:pos]
    path = list()
    for i in range(0,h):
        # print "sig[" + str(i) + "]:\t" + stringToHex(sig[pos:pos+n])
        path.append(sig[pos:pos+n])
        pos = pos + n
    return lmots_sig, path

def print_lms_sig(sig):
    lmots_sig, path = decode_lms_sig(sig)
    print_lmots_sig(lmots_sig)
    for i, e in enumerate(path):
        print "path[" + str(i) + "]:\t" + str(stringToHex(e))

def bytes_in_lms_sig():
    return bytes_in_lmots_sig() + h*n + 4

class lms_private_key(object):

    # Algorithm for computing root and other nodes (alternative to Algorithm 6)
    #
    def T(self, j):
        # print "T(" + str(j) + ")"
        if (j >= 2**h):
            self.nodes[j] = H(self.pub[j - 2**h] + self.I + uint32ToString(j) + D_LEAF)
            return self.nodes[j]
        else:
            self.nodes[j] = H(self.T(2*j) + self.T(2*j+1) + self.I + uint32ToString(j) + D_INTR)
            return self.nodes[j]

    def __init__(self):
        self.I = entropySource.read(31)
        self.priv = list()
        self.pub = list()
        for q in range(0, 2**h):
            # print "generating " + str(q) + "th OTS key"
            ots_priv = lmots_gen_priv()
            ots_pub = lmots_gen_pub(ots_priv, self.I, uint32ToString(q))
            self.priv.append(ots_priv)
            self.pub.append(ots_pub)
        self.leaf_num = 0
        self.nodes = {}
        self.lms_public_key = self.T(1)

    def num_sigs_remaining():
        return 2**h - self.leaf_num

    def printHex(self):
        for i, p in enumerate(self.priv):
            print "priv[" + str(i) + "]:"
            for j, x in enumerate(p):
                print "x[" + str(j) + "]:\t" + stringToHex(x)
            print "pub[" + str(i) + "]:\t" + stringToHex(self.pub[i])
        for t, T in self.nodes.items():
            print "T(" + str(t) + "):\t" + stringToHex(T)
        print "pub: \t" + stringToHex(self.lms_public_key)

    def get_public_key(self):
        return self.lms_public_key

    def get_path(self, leaf_num):
        node_num = leaf_num + 2**h
        # print "signing node " + str(node_num)
        path = list()
        while node_num > 1:
            if (node_num % 2):
                # print "path" + str(node_num - 1) + ": " + stringToHex(self.nodes[node_num - 1])
                path.append(self.nodes[node_num - 1])
            else:
                # print "path " + str(node_num + 1) + ": " + stringToHex(self.nodes[node_num + 1])
                path.append(self.nodes[node_num + 1])
            node_num = node_num/2
        return path

    def sign(self, message):
        if (self.leaf_num >= 2**h):
            return ""
        sig = lmots_gen_sig(self.priv[self.leaf_num], self.I, uint32ToString(self.leaf_num), message)
        # C, I, q, y = decode_lmots_sig(sig)
        path = self.get_path(self.leaf_num)
        leaf_num = self.leaf_num
        self.leaf_num = self.leaf_num + 1
        return encode_lms_sig(sig, path)


class lms_public_key(object):

    def __init__(self, value):
        self.value = value

    def verify(self, message, sig):
        lmots_sig, path = decode_lms_sig(sig)
        C, I, q, y = decode_lmots_sig(lmots_sig)       # note: only q is actually needed here
        node_num = stringToUint(q) + 2**h
        # print "verifying node " + str(node_num)
        pathvalue = iter(path)
        tmp = lmots_sig_to_pub(lmots_sig, message)
        tmp = H(tmp + I + uint32ToString(node_num) + D_LEAF)
        while node_num > 1:
            # print "S(" + str(node_num) + "):\t" + stringToHex(tmp)
            if (node_num % 2):
                # print "adding node " + str(node_num - 1)
                tmp = H(pathvalue.next() + tmp + I + uint32ToString(node_num/2) + D_INTR)
            else:
                # print "adding node " + str(node_num + 1)
                tmp = H(tmp + pathvalue.next() + I + uint32ToString(node_num/2) + D_INTR)
            node_num = node_num/2
        # print "pubkey: " + stringToHex(tmp)
        if (tmp == self.value):
            return 1
        else:
            return 0




# test LMS signatures
#

print "LMS test"

lms_priv = lms_private_key()
lms_pub = lms_public_key(lms_priv.get_public_key())

# lms_priv.printHex()

for i in range(0, 2**h):
    sig = lms_priv.sign(message)

    print "LMS signature byte length: " + str(len(sig))

    # print_lms_sig(sig)

    print "true positive test"
    if (lms_pub.verify(message, sig) == 1):
        print "passed: LMS message/signature pair is valid"
    else:
        print "failed: LMS message/signature pair is invalid"

    print "false positive test"
    if (lms_pub.verify("other message", sig) == 1):
        print "failed: LMS message/signature pair is valid (expected failure)"
    else:
        print "passed: LMS message/signature pair is invalid as expected"

# Hierarchical LMS signatures (HLMS)

def encode_hlms_sig(pub2, sig1, lms_sig):
    result = uint32ToString(hlms_sha256_n32_l2)
    result = result + pub2
    result = result + sig1
    result = result + lms_sig
    return result

def decode_hlms_sig(sig):
    typecode = sig[0:4]
    if (typecode != uint32ToString(hlms_sha256_n32_l2)):
        print "error decoding signature; got typecode " + stringToHex(typecode) + ", expected: " + stringToHex(uint32ToString(hlms_sha256_n32_l2))
        return ""
    pub2 = sig[4:36]
    lms_sig_len = bytes_in_lms_sig()
    sig1 = sig[36:36+lms_sig_len]
    lms_sig = sig[36+lms_sig_len:36+2*lms_sig_len]
    return pub2, sig1, lms_sig

def print_hlms_sig(sig):
    pub2, sig1, lms_sig = decode_hlms_sig(sig)
    print "pub2:\t" + stringToHex(pub2)
    print "sig1: "
    print_lms_sig(sig1)
    print "sig2: "
    print_lms_sig(lms_sig)

class hlms_private_key(object):
    def __init__(self):
        self.prv1 = lms_private_key()
        self.init_level_2()

    def init_level_2(self):
        self.prv2 = lms_private_key()
        self.sig1 = self.prv1.sign(self.prv2.get_public_key())

    def get_public_key(self):
        return self.prv1.get_public_key()

    def sign(self, message):
        lms_sig = self.prv2.sign(message)
        if (lms_sig == ""):
            print "refreshing level 2 public/private key pair"
            self.init_level_2()
            lms_sig = self.prv2.sign(message)
        return encode_hlms_sig(self.prv2.get_public_key(), self.sig1, lms_sig)
class hlms_public_key(object):
    def __init__(self, value):
        self.pub1 = lms_public_key(value)

    def verify(self, message, sig):
        pub2, sig1, lms_sig = decode_hlms_sig(sig)
        if (self.pub1.verify(pub2, sig1) == 1):
            if (lms_public_key(pub2).verify(message, lms_sig) == 1):
                return 1
            else:
                print "pub2 verification of lms_sig did not pass"
        else:
            print "pub1 verification of sig1 did not pass"
        return 0



print "HLMS testing"

hlms_prv = hlms_private_key()

hlms_pub = hlms_public_key(hlms_prv.get_public_key())

for i in range(0, 4096):

    sig = hlms_prv.sign(message)

    # print_hlms_sig(sig)

    print "HLMS signature byte length: " + str(len(sig))

    print "testing verification (" + str(i) + "th iteration)"
    print "true positive test"
    if (hlms_pub.verify(message, sig) == 1):
        print "passed; HLMS message/signature pair is valid"
    else:
        print "failed; HLMS message/signature pair is invalid"

        print "false positive test"
        if (hlms_pub.verify("other message", sig) == 1):
            print "failed; HLMS message/signature pair is valid (expected failure)"
        else:
            print "passed; HLMS message/signature pair is invalid as expected"        
