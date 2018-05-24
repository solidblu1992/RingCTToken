#from bn128_curve import *
from optimized_curve import *
import sha3

#alt_bn_128 curve parameters
Ncurve = curve_order
Pcurve = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000
NullPoint = (FQ(0), FQ(0), FQ(0))
counters = [0]*32

useShamir = True    #Flag True to use Shamir's Trick to compute (a*A + b*B) effectively
useWindowed = True  #Flag True to use windowed EC Multiplication

def bytes_to_int(bytes):
    result = 0

    for b in bytes:
        result = result * 256 + int(b)

    return result

def int_to_iterable(i):
    x = []
    bits = 0
    while i > 0:
        y = i & (0xFF << bits)
        x = [(y >> bits)] + x
        i = i - y
        bits = bits + 8

    return x

def int_to_bytes64(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))

    if (len(x) < 64):
        y = bytes(64 - len(x))
        x = y+x

    return x

def int_to_bytes32(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff))

    if (len(x) < 32):
        y = bytes(32 - len(x))
        x = y+x

    return x

def int_to_bytes20(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffffffffffff))

    if (len(x) < 20):
        y = bytes(20 - len(x))
        x = y+x

    return x

def int_to_bytes16(i):
    x = bytes(int_to_iterable(i% 0xffffffffffffffffffffffffffffffff))

    if (len(x) < 16):
        y = bytes(16 - len(x))
        x = y+x

    return x

def to_point(x, y):
    return (FQ(x), FQ(y), FQ(1))

def bytes_to_str(b, N=32):
    s = hex(b)

    if (len(s) < (2*N+2)):
        y = (2*N+2) - len(s)
        y = "0" * y
        s = "0x" + y + s[2:]

    return s

def point_to_str(p):
    if (type(p) != tuple):
        p = ExpandPoint(p)

    p = normalize(p)
    
    s = (bytes_to_str(p[0].n) + ",\n" + bytes_to_str(p[1].n))
    return s

def hash_of_int(i):
    hasher = sha3.keccak_256(int_to_bytes32(i))
    x = bytes_to_int(hasher.digest())
    return x

def hash_of_point(p):
    p = normalize(p)
    hasher = sha3.keccak_256()
    hasher.update(int_to_bytes32(p[0].n))
    hasher.update(int_to_bytes32(p[1].n))
    x = bytes_to_int(hasher.digest())
    return x

def hash_to_point(p):
    p = normalize(p)
    hasher = sha3.keccak_256()
    hasher.update(int_to_bytes32(p[0].n))
    hasher.update(int_to_bytes32(p[1].n))
    x = bytes_to_int(hasher.digest()) % Pcurve

    onCurve = False
    while(not onCurve):
        y_squared = (pow(x, 3, Pcurve) + 3) % Pcurve
        y = pow(y_squared, (Pcurve+1)//4, Pcurve)

        onCurve = (pow(y,2,Pcurve) == y_squared)

        if(not(onCurve)):
            x = x + 1

    return (FQ(x), FQ(y), FQ(1))

def add_point_to_hasher(hasher, point):
    point = normalize(point)
    hasher.update(int_to_bytes32(point[0].n))
    hasher.update(int_to_bytes32(point[1].n))
    return hasher

#Definition of H = hash_to_point(G1)
H = hash_to_point(G1)

def KeyImage(xk):
    return multiply(hash_to_point(multiply(G1,xk)), xk)

#Utility Functions
def CompressPoint(Pin):
    if (type(Pin) != tuple):
        return Pin
    
    Pin = normalize(Pin)
    Pout = Pin[0].n
    if ( (Pin[1].n & 0x1) == 0x1):
        Pout = Pout | ECSignMask

    return Pout

def ExpandPoint(Pin):
    import math
    
    x = Pin & (~ECSignMask)
    y_squared = (pow(x,3,Pcurve) + 3) % Pcurve
    y = pow(y_squared, (Pcurve+1)//4, Pcurve)

    if ((Pin & ECSignMask) == 0):
        if ( (y & 0x1) == 0 ):
            Pout = (FQ(x), FQ(y), FQ(1))
        else:
            Pout = (FQ(x), FQ(Pcurve-y), FQ(1))
    else:
        if ( (y & 0x1) == 0 ):
            Pout = (FQ(x), FQ(Pcurve-y), FQ(1))
        else:
            Pout = (FQ(x), FQ(y), FQ(1))

    return Pout

def getRandom(count=1):
    import random

    if (count == 1):
        out = (random.SystemRandom().getrandbits(254) % Ncurve)
    else:
        out = []
        for i in range(0, count):
            out = out + [random.SystemRandom().getrandbits(254) % Ncurve]

    return out


def getRandomUnsafe(seed=None):
    import random
    if (seed != None):
        random.seed(seed)
        
    out = (random.getrandbits(254) % Ncurve)

    return out

def ExpandCompressTest():
    for i in range(0, 20):
        x = getRandom()
        point = multiply(G1, x)
        cpoint = CompressPoint(point)
        point2 = ExpandPoint(CompressPoint(point))
    
        print("Test[" + str(i) + "]...", end="")
        if (not eq(point, point2)):
            print("Failure! ", end="")

            if ((point[1].n & 0x1) == 0x1):
                print("point is odd")
            
            #print("point = " + hex(point[0].n))
            #print("cpoint = " + hex(cpoint))
        else:
            print("Success!")

#Elliptic Curve Multiplication
if (useWindowed):
    def precompute_points(P, wBits=5):        
        #Calculate Precompiled Points: [1, 3, 5, ...]*P
        wPowOver4 = 1 << (wBits-2)
        P_pre = [None]*wPowOver4
        P_pre[0] = P
        P2 = double(P)
        
        for i in range(1, len(P_pre)):
            P_pre[i] = add(P_pre[i-1], P2)

        return P_pre
    
    G_pre = precompute_points(G1)
    H_pre = precompute_points(H)
    
    def multiply(P, s, wBits=5):
        wPow = (1 << wBits)
        wPowOver2 = wPow // 2

        if (eq(P, G1)):
            P_pre = G_pre
        elif (eq(P, H)):
            P_pre = H_pre
        else:
            P_pre = precompute_points(P, wBits)
        
        #Get NAF digits
        dj = []
        i = 0
        while (s > 0):
            if (s % 2) == 1:
                d = s % wPow
                if (d > wPowOver2):
                    d = d - wPow
                    
                s -= d
                
                dj += [d]
            else:
                dj += [0]

            s = s // 2
            i = i + 1

        Q = NullPoint
        for j in reversed(range(0, i)):
            Q = double(Q)
            if (dj[j] > 0):
                index = (dj[j] - 1) // 2
                Q = add(Q, P_pre[index])
            elif (dj[j] < 0):
                index = (-dj[j] - 1) // 2
                Q = add(Q, neg(P_pre[index]))
            
        return Q

    def Multiply_TimeTrials(N=300):
        import time
        r = getRandom(N)
        t0 = time.time()
        for i in range(0, len(r)):
            P = multiply_naive(G1, r[i])
        t0 = time.time() - t0
        print("naive() => " + str(t0) + "s")

        t1 = time.time()
        for i in range(0, len(r)):
            P = multiply(G1, r[i])
        t1 = time.time() - t1
        print("windowed_pre() => " + str(t1) + "s")
        print("% => " + str((t0-t1)*100/t1))

        Gi = hash_to_point(H)
        t2 = time.time()
        for i in range(0, len(r)):
            P = multiply(Gi, r[i])
        t2 = time.time() - t2
        print("windowed() => " + str(t2) + "s")
        print("% => " + str((t0-t2)*100/t2))
else:
    def multiply(P, s):
        return multiply_naive(P, s)

#shamir2 and shamir 3 are variations on multiply() using Shamir's Trick - Multiexponentiation
def find_msb(s):
    x = (1 << 255)
    while (s & x == 0):
        x = x >> 1

    return x

if (useShamir):
    def shamir(P, s):
        b = len(P)
        assert(b == len(s))

        if (b == 1):
            return multiply(P[0], s[0])

        points = [NullPoint]*(2**b-1)

        bit = 1
        for i in range(0, b):
            for j in range(1, len(points)+1):
                if ((j & bit) > 0):
                    points[j-1] = add(points[j-1], P[i])

            bit = bit << 1

        x = find_msb(max(s))
        Pout = NullPoint

        while (x > 0):
            Pout = double(Pout)

            i = 0
            bit = 1
            for j in range(0, b):
                if ((x & s[j]) > 0):
                    i = i + bit

                bit = bit << 1

            if (i > 0):
                Pout = add(Pout, points[i-1])
                    
            x = x >> 1

        return Pout

    def Shamir_TimeTrials(N=100, n=2):
        import time

        #Pick random Numbers
        r = []
        for i in range(0, N):
            r = r + [getRandom(n)]

        #Get generator points
        G = [G1] + [NullPoint]*(n-1)
        for j in range(1, n):
                G[j] = hash_to_point(G[j-1])

        #Test naive method
        ms = time.time()
        for i in range(0, N):
            P = multiply(G[0], r[i][0])
            for j in range(1, n):
                P = add(P, multiply(G[j], r[i][j]))
                
        ms_end = time.time()
        t0 = ms_end-ms
        print("naive() => " + str(t0) + "s")

        #Test Shamir's trick
        ms = time.time()
        for i in range(0, N):
            P = shamir(G, r[i])
        ms_end = time.time()
        t1 = ms_end-ms
        print("shamir() => " + str(t1) + "s")
        print("% => " + str((t0-t1)*100/t0))
else:
    def shamir(P, s):
        if (len(P) == 1):
            return multiply(P[0], s[0])
        
        assert(len(P) == len(s))

        Pout = multiply(P[0], s[0])
        for i in range(1, len(P)):
            Pout = add(Pout, multiply(P[i], s[i]))
            
        return Pout
