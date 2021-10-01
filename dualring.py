from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
#from msp import MSP
import hashlib
import time

debug = False


class DualRing(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.sk = {}
        self.pk = None


    def setup(self):
        """
        Generates public parameters.
        """

        if debug:
            print('\nSetup algorithm:\n')
            
        g = self.group.random(G1)
        h = self.group.random(G2)
        hvec = []
        tvec = [0, 1, 2, 1, 2, 1]
        t = 12121
        
        # i = 5, l = 5
        for i in range(0,6):
            hvec.append(self.group.random(G2))
            
        Ft = hvec[0]
        for i in range(1, 6):
            Ft *= hvec[i] ** tvec[i]
        
        pp = {'g':g, 'h':h, 'hvec':hvec, 'Ft':Ft}

        return pp


    def keygen(self, pp):
        """
        Generate a key pair
        """

        if debug:
            print('\nKey generation algorithm:\n')
        
        g = pp['g']
        h = pp['h']

        # (sk, pk)
        SK = []
        r = self.group.random(ZR)
        sk = self.group.random(ZR)
        tmp1 = g ** r
        tmp2 = h ** sk * pp['Ft'] ** r
        pk = g ** sk
        SK.append(tmp1)
        SK.append(tmp2)
        
        return SK, pk
       
        
    def sign(self, pp, sk, pk, m):
        """
        Generate a signature
        pk: a set of public keys
        sk: signer's private key
        """
        g = pp['g']
        h = pp['h']
        
        # step 1
        cs = [1]
        for i in range(1,len(pk)):
            cs.append(self.group.random(ZR))
            
        rhat1 = self.group.random(ZR)
        rhat2 = self.group.random(ZR)
        rhat = rhat1 + rhat2
        tmp = 1
        for j in range(1, len(pk)):
            tmp *= pk[j] ** cs[j]
        R = pair(tmp, h) / pair(g ** rhat, pp['Ft'])    
        
        # step 2
        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(R)) 
        c_ = sha256.hexdigest()
        seed = str(c_) + m
        tmp = 1
        for i in range(0,len(pk)):
            tmp *= pk[i]
        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(tmp)) 
        c_ = sha256.hexdigest()
        seed = seed + str(c_)     
        c = self.group.hash(seed, ZR)
        for j in range(1, len(pk)):
           c = c + cs[j]
        cs[0] = c
           
        # step 3
        sigma1 = sk[1] ** c * pp['Ft'] ** rhat1
        sigma2 = g**rhat2 / (sk[0] ** c)
        
        
        sig = [sigma1, sigma2, cs]      
        
        return sig


    def verify(self, pp, sig, pk, m):
        """
        Verify a signature
        """
        g = pp['g']
        h = pp['h']
        sigma1 = sig[0]
        sigma2 = sig[1]
        cs = sig[2]
        
        A = pair(g, sigma1)
        B = pair(sigma2, pp['Ft'])
        tmp = pk[0] ** cs[0]
        for j in range(1, len(pk)):
            tmp *= pk[j] ** cs[j]
        C = pair(tmp, h)
        Rprime = C / (A * B)
        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(Rprime)) 
        c_ = sha256.hexdigest()
        seed = str(c_) + m
        tmp = 1
        for i in range(0,len(pk)):
            tmp *= pk[i]
        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(tmp)) 
        c_ = sha256.hexdigest()
        seed = seed + str(c_)        
        cprime = self.group.hash(seed, ZR)
        
        tmp1 = 0
        for j in range(1, len(pk)):
            tmp1 += cs[j]
        
        if (cprime == cs[0] - tmp1):
            return 0
        else:
            return 1
            
            
        return 0
        
       
       
        
    
