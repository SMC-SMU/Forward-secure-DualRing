from charm.toolbox.pairinggroup import PairingGroup, GT, ZR, pair
from dualring import DualRing
import time


def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    
    dualring = DualRing(pairing_group)

    pp = dualring.setup()
    sk = []
    pk = []
    rds = 100
    
    for num_u in range(10, 101, 10):
        sum_t = 0
        for i in range(0, rds):
            sk = []
            pk = []
            tmp = 0
            for j in range(0,num_u):
                start = time.time()
                a, b = dualring.keygen(pp)
                end = time.time()
                tmp += end - start
                sk.append(a)
                pk.append(b)
            sum_t += tmp
        key_t = sum_t / rds
        
        m = "abc"
        sum_t = 0
        for i in range(0,rds):
            start = time.time()
            sig = dualring.sign(pp, sk[0], pk, m)
            end = time.time()
            sum_t += end - start
        sign_t = sum_t / rds
        
        sum_t = 0
        for i in range(0,rds):  
            start = time.time()  
            dualring.verify(pp, sig, pk, m)
            end = time.time()
            sum_t += end - start
        ver_t = sum_t / rds
    
        print("len(pk) = " + str(num_u))
        print("key_t: " + str(key_t))
        print("sign_t: " + str(sign_t))
        print("ver_t: " + str(ver_t))




if __name__ == "__main__":
    debug = True
    main()
