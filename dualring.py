from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
import hashlib
import time

debug = False


class DualRing(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.sk = {}
        self.pk = None
        self.pp = {}


    def setup(self):
        """
        Generates public parameters.
        """

        if debug:
            print('\nSetup algorithm:\n')
            
        g = self.group.random(G1)
        h = self.group.random(G1)
        self.pp = {'g':g, 'h':h}

        return self.pp


    def keygen(self, pp):
        """
        Generate a key pair
        """

        if debug:
            print('\nKey generation algorithm:\n')
        
        g = self.pp['g']
        h = self.pp['h']

        # (sk, pk)
        x1 = self.group.random(ZR)
        x2 = self.group.random(ZR)
        y1 = self.group.random(ZR)
        y2 = self.group.random(ZR)
        kp0 = y1 * y2
        kp1 = x1 * y2 + x2 * y1
        kp2 = x1 * x2
        pk = pair(g**kp2, g) * pair(g**kp1, h) * pair(h**kp0, h)
        
        self.sk = {'x1':x1, 'x2':x2, 'y1':y1, 'y2':y2, 'kp0':kp0, 'kp1':kp1, 'kp2':kp2}
        self.pk = pk
        
        return self.sk, self.pk
       
        
    def sign(self, pp, sk, pk, m):
        """
        Generate a signature
        """
        g = self.pp['g']
        h = self.pp['h']
        r0 = self.group.random(ZR)
        r1 = self.group.random(ZR)
        r2 = self.group.random(ZR)
        
        c_list = [1]
        for i in range(1,len(pk)):
            c_list.append(self.group.random(ZR))
        tmp = 1
        start = time.time()
        for i in range(1,len(pk)):
            tmp *= pk[i] ** c_list[i]
        K = pair(g**r2,g) * pair(g**r1,h) * pair(h**r0, h) * tmp
        
        
        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(K))  
        c_ = sha256.hexdigest()
        seed = str(c_) + m
        c = self.group.hash(seed, ZR)
        tmp2 = 1
        for i in range(1,len(pk)):
            tmp2 += c_list[i]  
        c_list[0] = c + tmp2
        r0_bar = r0 - c_list[0] * sk['kp0']
        r1_bar = pair(g**(r1-c_list[0]*sk['kp1']),h) * pair(g**(r2-c_list[0]*sk['kp2']),g)
        sig = {'r0_bar':r0_bar, 'r1_bar':r1_bar, 'c_list':c_list}        
        
        return sig


    def verify(self, pp, sig, pk, m):
        """
        Verify a signature
        """
        g = self.pp['g']
        h = self.pp['h']
        
        tmp3 = 1
        for i in range(0,len(pk)):
            tmp3 *= pk[i] ** sig['c_list'][i]        
        K_prime = pair(h**sig['r0_bar'], h) * sig['r1_bar'] * tmp3
        
        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(K_prime))  
        c_ = sha256.hexdigest()
        seed = str(c_) + m
        c_prime = self.group.hash(seed, ZR)
        
        tmp4 = 1
        for i in range(1,len(pk)):
            tmp4 += sig['c_list'][i]
        if (c_prime == sig['c_list'][0]-tmp4):
            return 0
        else:
            return 1
            
        return 0
        
       
       
        
    
