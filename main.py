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
    
    for i in range(0,100):
        a, b = dualring.keygen(pp)
        sk.append(a)
        pk.append(b)
        
    m = "abc"
    sum_t = 0
    for i in range(0,100):
        start = time.time()
        sig = dualring.sign(pp, sk[0], pk, m)
        end = time.time()
        sum_t += end - start
    sign_t = sum_t / 100
        
    sum_t = 0
    for i in range(0,100):  
        start = time.time()  
        dualring.verify(pp, sig, pk, m)
        end = time.time()
        sum_t += end - start
    ver_t = sum_t / 100
    
    print(sign_t)
    print(ver_t)



if __name__ == "__main__":
    debug = True
    main()
