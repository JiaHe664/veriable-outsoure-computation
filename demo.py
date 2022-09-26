
from charm.core.math.integer import integer,randomPrime,bitsize,int2Bytes
import charm.core.math.integer as Integer
from BFV import *
from helper import *
from pypbc import *


class Param():
    def __init__(self):
        pass
    def setParam(self,N2,N,g):
        self.N2 = N2
        self.N = N
        self.g = g

class BCP():
    def __init__(self,secparam=1024,param = None):
        if param:
            self.N2 = param.N2
            self.N = param.N
            self.g = param.g   
        else:
            self.p, self.q = randomPrime(int(secparam/2),True), randomPrime(int(secparam/2),True) 
            self.pp = (self.p -1)/2
            self.qq = (self.q - 1)/2
            self.N = self.p * self.q
            while True: 
                if bitsize(self.N) ==secparam and len(int2Bytes(self.N)) == int(secparam/8) and int2Bytes(self.N)[0] &128 !=0:
                    break
                self.p, self.q = randomPrime(int(secparam/2),True), randomPrime(int(secparam/2),True) 
                self.pp = (self.p -1)/2
                self.qq = (self.q - 1)/2
                self.N = self.p * self.q
            self.N2 = self.N**2
            self.g = Integer.random(self.N2)
            one = integer(1)% self.N2
            while True: #choose a good g
                self.g = Integer.random(self.N2)
                self.g = integer((int(self.g)-1)*(int(self.g)-1))% self.N2
                if self.g == one:
                    continue
                tmp = self.g**self.p %self.N2
                if tmp == one:
                    continue
                tmp = self.g**self.pp % self.N2
                if tmp == one:
                    continue
                tmp = self.g**self.q %self.N2
                if tmp == one:
                    continue
                tmp = self.g**self.qq %self.N2
                if tmp == one:
                    continue
                tmp =self.g**(self.p*self.pp) % self.N2
                if tmp == one:
                    continue 
                tmp = self.g**(self.p*self.q) %self. N2
                if tmp== one:
                    continue 
                tmp = self.g**(self.p*self.qq) % self.N2
                if tmp == one:
                    continue 
                tmp = self.g**(self.pp*self.q) % self.N2
                if tmp == one:
                    continue 
                tmp = self.g**(self.pp*self.qq) % self.N2
                if tmp == one:
                    continue 
                tmp = self.g**(self.q*self.qq) % self.N2
                if tmp == one:
                    continue
                tmp = self.g**(self.q*self.qq) % self.N2
                if tmp == one:
                    continue
                tmp = self.g**(self.p*self.pp*self.q) % self.N2
                if tmp == one:
                    continue   
                tmp =self.g**(self.p*self.pp*self.qq) % self.N2
                if tmp == one:
                    continue
                tmp =self.g**(self.p*self.q*self.qq) % self.N2
                if tmp == one:
                    continue
                tmp =self.g**(self.pp*self.q*self.qq) % self.N2
                if tmp == one:
                    continue  
                break 
    
    def GetParam(self):
        param = Param()
        param.setParam(self.N2, self.N, self.g, self.k)
        return param
    
    def KeyGen(self):
        tmp = self.N2 /2
        sk = Integer.random(tmp) % self.N2
        pk = (self.g**sk) % self.N2
        return pk,sk

    def ReKeyGen(self,sk):
        tmp = self.N2 /4
        re_key = Integer.random(tmp) % self.N2
        tmp_sk = re_key*sk
        # print("111111111111111")
        # print(integer(tmp_sk))
        # print("2222222222222222")
        # print(integer(re_key*sk))
        return re_key, tmp_sk
    
    def Encrypt(self,pk,plaintext):
        r = Integer.random(self.N/4) % self.N2
        A = (pk** r ) % self.N2 
        B1 = (self.N*plaintext+1)% (self.N2)
        B2 = (self.g**r) % (self.N2)
        B = B1*B2 % self.N2
        ciphertext = {"A":A,"B":B}
        return ciphertext
    
    def Decrypt(self,ciphertext,sk):
        t1 = integer((int((ciphertext['B']**sk)*(ciphertext['A']**-1)) -1)*int(sk**-1)) % self.N2
        m = integer(t1) / self.N
        return m
    
    def ReEncrypt(self,ciphertext,re_key):
        reenc_ciphertext = {}
        reenc_ciphertext['A'] = (ciphertext['A']**re_key) % self.N2
        reenc_ciphertext['B'] = ciphertext['B']

        return reenc_ciphertext

    def multiply(self,ciphertext1,ciphertext2):
        ciphertext={}
        ciphertext['A'] = ciphertext1['A'] * ciphertext2['A']
        ciphertext['B'] = ciphertext1['B'] * ciphertext2['B'] 
        return ciphertext

    def exponentiate(self,ciphertext,m):
        text={}    
        text['A'] = ciphertext['A'] **m % self.N2
        text['B'] = ciphertext['B'] **m % self.N2
        return text  

    
if __name__ == "__main__":

##############################################  outsource computation   ########################################

# model owner

    # initial model f_eval
    cols = 3
    rows = 3    
    f_eval = []
    for r_idx in range(rows):
        tmp = []
        for c_idx in range(cols):
            tmp.append(Integer.random(100))
        f_eval.append(tmp)
    print("------------------------")
    print("the plaintext of f_eval =", f_eval)  

    # initial bcp
    bcp = BCP()
    pk,sk = bcp.KeyGen()
    print("------------------------")
    print("pk is:",pk,"\nsk is:",sk) 

    # initial r, g_r, s, g_s
    r = [] # blinding vector r
    for r_idx in range(rows):
        r.append(Integer.random(bcp.N2))
    print("------------------------")
    print("the blinding vector r =", r) 
    g_r = []
    for r_idx in range(rows):
        g_r.append(bcp.g**r[r_idx])
    print("------------------------")
    print("g_r =", g_r)
    s = []
    for c_idx in range(cols):
        sum = 0
        for r_idx in range(rows):
            sum += int(r[r_idx])*int(f_eval[r_idx][c_idx])
        s.append(sum)
    print("------------------------")
    print("the vector s = rf =", s)   
    g_s =[]
    for c_idx in range(cols):
        g_s.append(bcp.g**s[c_idx])
    print("------------------------")
    print("g_s =", g_s)

    # encrypt the model f_eval
    f_eval_ciphertext =[]
    for r_idx in range(rows):
        tmp = []
        for c_idx in range(cols):
            tmp.append(bcp.Encrypt(pk,int(f_eval[r_idx][c_idx])))
        f_eval_ciphertext.append(tmp)  
    print("-------------------------")
    print("ciphertext of f_eval on bcp_variant is:",f_eval_ciphertext)


    # initial reEncryption scheme
    re_key, tmp_sk = bcp.ReKeyGen(sk)   
    print("------------------------")
    print("reEncryption key is:",re_key,"temporary key is:",tmp_sk)

# user

    x = []   # evaluated value
    for c_idx in range(cols):
        x.append(Integer.random(100))
    print("-------------------------")
    print("the evaluated value x = ",x)


    # initial BFV scheme

    PD = 0 # 0: generate -- 1: pre-defined

    if PD == 0:
        # Select one of the parameter sets below
        # t = 16;   n, q, psi = 1024 , 132120577         , 73993                # log(q) = 27
        # t = 256;  n, q, psi = 2048 , 137438691329      , 22157790             # log(q) = 37
        t = 1024; n, q, psi = 4096 , 288230376135196673, 60193018759093       # log(q) = 58

        # other necessary parameters
        psiv= modinv(psi,q)
        w   = pow(psi,2,q)
        wv  = modinv(w,q)
    else:
        # Enter proper parameters below
        t, n, logq = 16, 1024, 27
        # t, n, logq = 256, 2048, 37
        # t, n, logq = 1024, 4096, 58

        # other necessary parameters (based on n and log(q) determine other parameter)
        q,psi,psiv,w,wv = ParamGen(n,logq) 

    # Determine mu, sigma (for discrete gaussian distribution)
    mu    = 0
    sigma = 0.5 * 3.2

    # Determine T, p (for relinearization and galois keys) based on noise analysis 
    T = 256
    p = q**3 + 1

    # Generate polynomial arithmetic tables
    w_table    = [1]*n
    wv_table   = [1]*n
    psi_table  = [1]*n
    psiv_table = [1]*n
    for i in range(1,n):
        w_table[i]    = ((w_table[i-1]   *w)    % q)
        wv_table[i]   = ((wv_table[i-1]  *wv)   % q)
        psi_table[i]  = ((psi_table[i-1] *psi)  % q)
        psiv_table[i] = ((psiv_table[i-1]*psiv) % q)

    qnp = [w_table,wv_table,psi_table,psiv_table]

    # Generate BFV evaluator
    Evaluator = BFV(n, q, t, mu, sigma, qnp)

    # Generate Keys
    Evaluator.SecretKeyGen()
    Evaluator.PublicKeyGen()
    Evaluator.EvalKeyGenV1(T)
    Evaluator.EvalKeyGenV2(p)

    # print system parameters
    print(Evaluator)

    # Encode random messages into plaintext polynomials
    encoded_x = []
    for c_idx in range(cols):
        val = Evaluator.IntEncode(int(x[c_idx]))
        encoded_x.append(val)
        print("encoded_x[{0}] = {1}".format(c_idx, val))

    # Encrypt message
    x_ciphertext = []
    for c_idx in range(cols):
        val = Evaluator.Encryption(encoded_x[c_idx])
        x_ciphertext.append(val)
        print("--- encoded_x[{0}] is encrypted as ciphertext on BFV.".format(c_idx))
        print("* ct[0]: {}".format(val[0]))
        print("* ct[1]: {}".format(val[1]))


# server 1

    # r1 = Integer.random(bcp.N/4) % bcp.N2   # blind factor r1
    r1 = []
    for r_idx in range(rows):
        tmp = []
        for c_idx in range(cols):
            tmp.append(Integer.random(bcp.N))
        r1.append(tmp)
    print("------------------------")
    print("the factor r1 to blind the ciphertext of f_eval =", r1)
    r1_ciphertext = []
    for r_idx in range(rows):
        tmp = []
        for c_idx in range(cols):
            tmp.append(bcp.Encrypt(pk, int(r1[r_idx][c_idx])))
        r1_ciphertext.append(tmp)
    print("------------------------")
    print("the ciphertext of r1 =", r1_ciphertext)

    # calculate the ciphertext of r1+f
    r1_add_f_ciphertext = []
    for r_idx in range(rows):
        tmp = []
        for c_idx in range(cols):
            tmp.append(bcp.multiply(r1_ciphertext[r_idx][c_idx], f_eval_ciphertext[r_idx][c_idx]))
        r1_add_f_ciphertext.append(tmp) 
    print("------------------------")
    print("the ciphertext of r1+f on bcp  =", r1_add_f_ciphertext)  

    # reEncrypt the ciphertext of f_eval
    reenc_ciphertext = []
    for r_idx in range(rows):
        tmp = []
        for c_idx in range(cols):
            tmp.append(bcp.ReEncrypt(r1_add_f_ciphertext[r_idx][c_idx],re_key))
        reenc_ciphertext.append(tmp) 
    print("------------------------")
    print("the reEncrypted ciphertext of r1+f =", reenc_ciphertext)  

    # use r1 to blind the reenc_ciphertext of f_eval
    # blinded_f_ciphertext = bcp.exponentiate(reenc_f_ciphertext, int(r1))
    # print("------------------------")
    # print("the ciphertext of blinded f_eval =", blinded_f_ciphertext)  


# server 2

    # use temporary sk to decrypt the blinded ciphertext of f_eval
    r1_add_f_plaintext = []
    for r_idx in range(rows):
        tmp = []
        for c_idx in range(cols):
            tmp.append(bcp.Decrypt(reenc_ciphertext[r_idx][c_idx], tmp_sk))
        r1_add_f_plaintext.append(tmp) 
    print("------------------------")
    print("the plaintext of r1+f =", r1_add_f_plaintext)

    # calculate (r1+f)[x]
    blinded_fx_ciphertext = []
    for r_idx in range(rows):
        sum = 0
        for c_idx in range(cols):
            encoded_val = Evaluator.IntEncode(int(r1_add_f_plaintext[r_idx][c_idx]))    # encode r1_add_f to BGV scheme
            val_ciphertext = Evaluator.Encryption(encoded_val)
            val = Evaluator.HomomorphicMultiplication(val_ciphertext, x_ciphertext[c_idx])
            val = Evaluator.RelinearizationV1(val)
            if sum == 0:
                sum = val
            else:
                sum = Evaluator.HomomorphicAddition(sum, val)    
        blinded_fx_ciphertext.append(sum) 
    # blinded_fx_plaintext = Evaluator.Decryption(blinded_fx_ciphertext)
    # blinded_fx_plaintext_int = Evaluator.IntDecode(blinded_fx_plaintext)   
    # print("------------------------")
    # print("the plaintext of blinded fx = ",blinded_fx_plaintext_int) 

    # temp = int(blinded_f_plaintext) 
    # temp_1 = Evaluator.IntEncode(temp)
    # res = Evaluator.HomomorphicMultiplication(,x_ciphertext)
    # print("333333333333333333")
    # print(Evaluator.Decryption(res))
    # use 


# server 1

    # calculate r1[x]
    r1x_ciphertext = []
    for r_idx in range(rows):
        sum = 0
        for c_idx in range(cols):
            encoded_val = Evaluator.IntEncode(int(r1[r_idx][c_idx]))
            val_ciphertext = Evaluator.Encryption(encoded_val)
            val = Evaluator.HomomorphicMultiplication(val_ciphertext, x_ciphertext[c_idx])
            val = Evaluator.RelinearizationV1(val)
            if sum == 0:
                sum = val
            else:
                sum = Evaluator.HomomorphicAddition(sum, val)
        r1x_ciphertext.append(sum) 

    # remove r1x from (r1+f)x to get the ciphertext of fx
    fx_ciphertext = []
    for r_idx in range(rows):
        fx_ciphertext.append(Evaluator.HomomorphicSubtraction(blinded_fx_ciphertext[r_idx],r1x_ciphertext[r_idx]))


# user

    # r1x_plaintext = Evaluator.Decryption(r1x_ciphertext)
    # r1x_plaintext_int = Evaluator.IntDecode(r1x_plaintext)   
    # print("------------------------")
    # print("the plaintext of blinded fx = ", r1x_plaintext_int)
 
    # decrypt the ciphertext of fx to get the result
    fx_plaintext = []
    for r_idx in range(rows):
        val = Evaluator.Decryption(fx_ciphertext[r_idx])
        fx_plaintext.append(Evaluator.IntDecode(val)) 
    print("------------------------")
    print("the plaintext of fx = ", fx_plaintext) 
    tmp = []
    for r_idx in range(rows):
        sum = 0
        for c_idx in range(cols):
            sum += int(f_eval[r_idx][c_idx])*int(x[c_idx])
        tmp.append(sum)
    print(tmp)

# publicly verify   

    # use [fx] and [x] to verify g^s^[x] ?= g^r^[fx]

    # decode [fx] to a value
    decoded_fx = []
    for r_idx in range(rows):
        val = Evaluator.IntDecode(fx_ciphertext[r_idx][0]) + Evaluator.IntDecode(fx_ciphertext[r_idx][1])
        decoded_fx.append(val) 
    print("------------------------")
    print("the decoded value of [fx] = ", decoded_fx)   

    # decode [x] to a value
    decoded_x = []
    for c_idx in range(cols):
        val = Evaluator.IntDecode(x_ciphertext[c_idx][0]) + Evaluator.IntDecode(x_ciphertext[c_idx][1])
        decoded_x.append(val) 
    print("------------------------")
    print("the decoded value of [x] = ", decoded_x)  

    # verify 
    lv = 0      # lv is g^r^[fx] 
    for r_idx in range(rows):
        if lv == 0:
            lv = int(g_r[r_idx]**decoded_fx[r_idx])
        else:
            lv *= int(g_r[r_idx]**decoded_fx[r_idx])
    
    rv = 0
    for c_idx in range(cols):
        if rv == 0:
            rv = g_s[c_idx]**decoded_x[c_idx]
        else:
            rv *= g_s[c_idx]**decoded_x[c_idx]

    if lv == rv:
        print("g^s^[x] = g^r^[fx], the result is valid")  
    else:
        print("g^s^[x] != g^r^[fx], the result isn't valid")  
    # f_plaintext = (blinded_f_plaintext * int(r1**-1)) % bcp.N2
    # f_plaintext = blinded_f_plaintext - int(r1)
    # print("------------------------")
    # print("the plaintext of f_eval =", int(f_plaintext)) 

# privately verify
    lv = 0      # lv is g^r^[fx] 
    for r_idx in range(rows):
        if lv == 0:
            lv = g_r[r_idx]**fx_plaintext[r_idx]
        else:
            lv *= g_r[r_idx]**fx_plaintext[r_idx]
    
    rv = 0
    for c_idx in range(cols):
        if rv == 0:
            rv = g_s[c_idx]**x[c_idx]
        else:
            rv *= g_s[c_idx]**x[c_idx]

    print(lv,rv)

    if lv == rv:
        print("g^s^x = g^r^fx, the result is valid")  
    else:
        print("g^s^x != g^r^fx, the result isn't valid")  

