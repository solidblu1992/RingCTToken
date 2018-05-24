from util import *
import sha3

#Ring Signature Functions
class MSAG:
    msgHash = 0
    m = 0
    pub_keys = []
    signature = []

    def __init__(self, msgHash, m, pub_keys, signature):
        self.msgHash = msgHash
        self.m = m
        self.pub_keys = pub_keys
        self.signature = signature

    def RingHashFunction(msgHash, point):
        hasher = sha3.keccak_256()
        hasher.update(msgHash)
        hasher = add_point_to_hasher(hasher, point)
        return bytes_to_int(hasher.digest())

    def StartRing_NoHash(alpha):
        point = multiply(G1, alpha)
        return point

    def StartRing(msgHash, alpha):
        point = MSAG.StartRing_NoHash(alpha)
        return MSAG.RingHashFunction(msgHash, point)

    def CalculateRingSegment_NoHash(ck, sk, P):
        point = multiply(G1, sk)
        temp = multiply(P, ck)
        point = add(point, temp)

        return point

    def CalculateRingSegment(msgHash, ck, sk, P):
        point = MSAG.CalculateRingSegment_NoHash(ck, sk, P)
        return MSAG.RingHashFunction(msgHash, point)

    def CompleteRing(alpha, c, xk):
        s = (c * xk) % Ncurve
        s = Ncurve - s
        s = (alpha + s) % Ncurve
        return s

    #Pin is an m x (n-1) array.  Every key in Pin is used.
    #The keys for xk are calculated and substituted in at the appropriate time
    def Sign_CompactPin(m, msgHash, xk, indices, Pin, random):
        assert(len(xk) == m)
        assert(len(indices) == m)
        assert( (len(Pin) % m ) == 0)
        n = (len(Pin) // m) + 1
        assert( len(random) == m*n )

        #Initialize Output Arrays
        Pout = [0]*(m*n)
        signature = [0]*(m*n+1)

        #Initialize c1 hasher (total length of array + message hash)
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(2*m+1))
        hasher.update(msgHash)

        #Calulate 1st half of all rings (for c1 calculation)
        for i in range(0, m):
            #Make sure index is mod n
            indices[i] = indices[i] % n

            #Store public key for known private key
            Pout[m*indices[i]+i] = multiply(G1, xk[i])
            
            if (indices[i] == (n-1)):
                point = MSAG.StartRing_NoHash(random[m*indices[i]+i])
            else:
                ck = MSAG.StartRing(msgHash, random[m*indices[i]+i])

                for j in range((indices[i]+1)%n,(n-1)):
                    #Calculate array index for easy reference
                    index = m*j+i
                    
                    #Extract input public key
                    if (j > indices[i]):
                        point = Pin[index - m]
                    else:
                        point = Pin[index]

                    #Store public key in output
                    Pout[index] = point

                    #Calculate ring segment
                    ck = MSAG.CalculateRingSegment(msgHash, ck, random[index], point)

                    #Store s value
                    signature[index+1] = random[index]

                #Calculate last ring segment before c1
                index = m*(n-1) + i

                #Extract Public Key
                point = Pin[index-m]
                Pout[index] = point

                point = MSAG.CalculateRingSegment_NoHash(ck, random[index], point)

                #Store s value
                signature[index+1] = random[index]
                
            #Store update c1 hash
            hasher = add_point_to_hasher(hasher, point)

        #Store c1
        signature[0] = bytes_to_int(hasher.digest())

        #Calculate 2nd half of each ring
        for i in range(0, m):
            #Fetch c1
            ck = signature[0]

            #Calculate remaining ring segments
            for j in range(0, indices[i]):
                index = m*j+i

                #Extract public key
                point = Pin[index]
                Pout[index] = point

                #Calculate Ring Segment
                ck = MSAG.CalculateRingSegment(msgHash, ck, random[index], point)

                #Store s value
                signature[index+1] = random[index]

            #Close Ring
            index = m*indices[i] + i
            signature[index+1] = MSAG.CompleteRing(random[index], ck, xk[i])

        return MSAG(msgHash, m, Pout, signature)

    #Picks random numbers before signing
    def Sign_CompactPin_GenRandoms(m, msgHash, xk, indices, Pin):
        assert(len(xk) == m)
        assert(len(indices) == m)
        assert( (len(Pin) % m ) == 0)
        n = (len(Pin) // m) + 1
        
        #Create Random Numbers
        random = []
        for i in range(0, (m*n)):
            random = random + [getRandom()]

        return MSAG.Sign_CompactPin(msgHash, m, xk, indices, random)

    #Pin is an n x m array.  The elements corrosponding to xk in the array don't count however.
    #These keys are calculated from xk and substituted in at the appropriate time.
    def Sign(m, msgHash, xk, indices, Pin, random):
        assert(len(xk) == m)
        assert(len(indices) == m)
        assert( (len(Pin) % m ) == 0)
        n = (len(Pin) // m)
        assert( len(random) == m*n )

        #Initialize Output Arrays
        Pout = [0]*(m*n)
        signature = [0]*(m*n+1)

        #Initialize c1 hasher (total length of array + message hash)
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(2*m+1))
        hasher.update(msgHash)

        #Calulate 1st half of all rings (for c1 calculation)
        for i in range(0, m):
            #Make sure index is mod n
            indices[i] = indices[i] % n

            #Store public key for known private key
            Pout[m*indices[i]+i] = multiply(G1, xk[i])
            
            if (indices[i] == (n-1)):
                point = MSAG.StartRing_NoHash(random[m*indices[i]+i])
            else:
                ck = MSAG.StartRing(msgHash, random[m*indices[i]+i])

                for j in range((indices[i]+1)%n,(n-1)):
                    #Calculate array index for easy reference
                    index = m*j+i
                    
                    #Extract input public key
                    point = Pin[index]

                    #Store public key in output
                    Pout[index] = point

                    #Calculate ring segment
                    ck = MSAG.CalculateRingSegment(msgHash, ck, random[index], point)

                    #Store s value
                    signature[index+1] = random[index]

                #Calculate last ring segment before c1
                index = m*(n-1) + i

                #Extract Public Key
                point = Pin[index]
                Pout[index] = point

                point = MSAG.CalculateRingSegment_NoHash(ck, random[index], point)

                #Store s value
                signature[index+1] = random[index]
                
            #Store update c1 hash
            hasher = add_point_to_hasher(hasher, point)

        #Store c1
        signature[0] = bytes_to_int(hasher.digest())

        #Calculate 2nd half of each ring
        for i in range(0, m):
            #Fetch c1
            ck = signature[0]

            #Calculate remaining ring segments
            for j in range(0, indices[i]):
                index = m*j+i

                #Extract public key
                point = Pin[index]
                Pout[index] = point

                #Calculate Ring Segment
                ck = MSAG.CalculateRingSegment(msgHash, ck, random[index], point)

                #Store s value
                signature[index+1] = random[index]

            #Close Ring
            index = m*indices[i] + i
            signature[index+1] = MSAG.CompleteRing(random[index], ck, xk[i])

        return MSAG(msgHash, m, Pout, signature)

    def Sign_GenRandom(m, msgHash, xk, indices, Pin):
        assert(len(xk) == m)
        assert(len(indices) == m)
        assert( (len(Pin) % m ) == 0)
        n = (len(Pin) // m)
        
        #Create Random Numbers
        random = []
        for i in range(0, (m*n)):
            random = random + [getRandom()]

        return MSAG.Sign(m, msgHash, xk, indices, Pin, random)

    def Verify(self):
        #Check input parameter lengths
        m = self.m
        if (m == 0): return False
        if (len(self.pub_keys) % m != 0): return False
        n = len(self.pub_keys) // m
        if (n == 0): return False
        if (len(self.signature) != (m*n+1)): return False

        #Initialize c1 hasher (total length of array + message hash)
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(2*m+1))
        hasher.update(self.msgHash)

        #Calculate Rings
        for i in range(0, m):
            #Get c1
            ck = self.signature[0]

            #Calculate (n-1) ring segments
            for j in range(0, n-1):
                index = m*j+i
                ck = MSAG.CalculateRingSegment(self.msgHash, ck, self.signature[index+1], self.pub_keys[index])

            #Calculate last ring segment
            index = m*(n-1)+i
            point = MSAG.CalculateRingSegment_NoHash(ck, self.signature[index+1], self.pub_keys[index])

            #Update c1 hash
            hasher = add_point_to_hasher(hasher, point)
                
        #Check if ring is closed
        ck = bytes_to_int(hasher.digest())
        return (self.signature[0] == ck)

    def Print(self):
        print("MSAG Signature:")
        print("Dimensions: " + str(self.m) + " x " + str(len(self.pub_keys)//self.m))
        print("Message Hash: ")
        print(hex(bytes_to_int(self.msgHash)))

        print("Pub Keys:")
        for i in range(0, len(self.pub_keys)):
            print(hex(CompressPoint(self.pub_keys[i])))

        print("Signature:")
        for i in range(0, len(self.signature)):
            print(hex(self.signature[i]))

class MLSAG:
    msgHash = 0
    key_images = []
    pub_keys =[]
    signature = []

    def __init__(self, msgHash, key_images, pub_keys, signature):
        self.msgHash = msgHash
        self.key_images = key_images
        self.pub_keys = pub_keys
        self.signature = signature

    def LinkableRingHashFunction(msgHash, left, right):
        hasher = sha3.keccak_256()
        hasher.update(msgHash)
        hasher = add_point_to_hasher(hasher, left)
        hasher = add_point_to_hasher(hasher, right)
        return bytes_to_int(hasher.digest())

    def StartLinkableRing_NoHash(alpha, P):
        Lout = multiply(G1, alpha)
        Rout = multiply(hash_to_point(P), alpha)
        return (Lout, Rout)

    def StartLinkableRing(msgHash, alpha, P):
        (left, right) = MLSAG.StartLinkableRing_NoHash(alpha, P)
        return MLSAG.LinkableRingHashFunction(msgHash, left, right)

    def CalculateLinkableRingSegment_NoHash(ck, sk, P, I):
        Lout = multiply(G1, sk)
        temp = multiply(P, ck)
        Lout = add(Lout, temp)

        Rout = hash_to_point(P)
        Rout = multiply(Rout, sk)
        temp = multiply(I, ck)
        Rout = add(Rout, temp)

        return (Lout, Rout)

    def CalculateLinkableRingSegment(msgHash, ck, sk, P, I):
        (left, right) = MLSAG.CalculateLinkableRingSegment_NoHash(ck, sk, P, I)
        return MLSAG.LinkableRingHashFunction(msgHash, left, right)

    def CompleteRing(alpha, c, xk):
        s = (c * xk) % Ncurve
        s = Ncurve - s
        s = (alpha + s) % Ncurve
        return s

    #Pin is an m x (n-1) array.  Every key in Pin is used.
    #The keys for xk are calculated and substituted in at the appropriate time
    def Sign_CompactPin(m, msgHash, xk, indices, Pin, random):
        assert(len(xk) == m)
        assert(len(indices) == m)
        assert( (len(Pin) % m ) == 0)
        n = (len(Pin) // m) + 1
        assert( len(random) == m*n )

        #Initialize Output Arrays
        Pout = [0]*(m*n)
        signature = [0]*(m*n+1)
        I = [0]*m

        #Initialize c1 hasher (total length of array + message hash)
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(4*m+1))
        hasher.update(msgHash)

        #Calulate 1st half of all rings (for c1 calculation)
        for i in range(0, m):
            #Make sure index is mod n
            indices[i] = indices[i] % n

            #Calculate Key Image and Store for later use
            keyImage = multiply(hash_to_point(multiply(G1,xk[i])), xk[i])
            I[i] = keyImage

            #Store public key for known private key
            Pout[m*indices[i]+i] = multiply(G1, xk[i])
            
            if (indices[i] == (n-1)):
                (left, right) = MLSAG.StartLinkableRing_NoHash(random[m*indices[i]+i], multiply(G1, xk[i]))
            else:
                ck = MLSAG.StartLinkableRing(msgHash, random[m*indices[i]+i], multiply(G1, xk[i]))

                for j in range((indices[i]+1)%n,(n-1)):
                    #Calculate array index for easy reference
                    index = m*j+i
                    
                    #Extract input public key
                    if (j > indices[i]):
                        point = Pin[index - m]
                    else:
                        point = Pin[index]

                    #Store public key in output
                    Pout[index] = point

                    #Calculate ring segment
                    ck = MLSAG.CalculateLinkableRingSegment(msgHash, ck, random[index], point, keyImage)

                    #Store s value
                    signature[index+1] = random[index]

                #Calculate last ring segment before c1
                index = m*(n-1) + i

                #Extract Public Key
                point = Pin[index-m]
                Pout[index] = point

                (left, right) = MLSAG.CalculateLinkableRingSegment_NoHash(ck, random[index], point, keyImage)

                #Store s value
                signature[index+1] = random[index]
                
            #Store update c1 hash
            hasher = add_point_to_hasher(hasher, left)
            hasher = add_point_to_hasher(hasher, right)

        #Store c1
        signature[0] = bytes_to_int(hasher.digest())

        #Calculate 2nd half of each ring
        for i in range(0, m):
            #Fetch c1
            ck = signature[0]

            #Extract Key Image
            keyImage = I[i]

            #Calculate remaining ring segments
            for j in range(0, indices[i]):
                index = m*j+i

                #Extract public key
                point = Pin[index]
                Pout[index] = point

                #Calculate Ring Segment
                ck = MLSAG.CalculateLinkableRingSegment(msgHash, ck, random[index], point, keyImage)

                #Store s value
                signature[index+1] = random[index]

            #Close Ring
            index = m*indices[i] + i
            signature[index+1] = MLSAG.CompleteRing(random[index], ck, xk[i])

        return MLSAG(msgHash, I, Pout, signature)

    #Picks random numbers
    def Sign_CompactPin_GenRandom(m, msgHash, xk, indices, Pin):
        assert(len(xk) == m)
        assert(len(indices) == m)
        assert( (len(Pin) % m ) == 0)
        n = (len(Pin) // m) + 1
        
        #Create Random Numbers
        random = []
        for i in range(0, (m*n)):
            random = random + [getRandom()]

        return MLSAG.Sign_CompactPin(m, msgHash, xk, indices, Pin, random)

    #Pin is an n x m array.  The elements corrosponding to xk in the array don't count however.
    #These keys are calculated from xk and substituted in at the appropriate time.
    def Sign(m, msgHash, xk, indices, Pin, random):
        assert(len(xk) == m)
        assert(len(indices) == m)
        assert( (len(Pin) % m ) == 0)
        n = (len(Pin) // m)
        assert( len(random) == m*n )

        #Initialize Output Arrays
        Pout = [0]*(m*n)
        signature = [0]*(m*n+1)
        I = [0]*m

        #Initialize c1 hasher (total length of array + message hash)
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(4*m+1))
        hasher.update(msgHash)

        #Calulate 1st half of all rings (for c1 calculation)
        for i in range(0, m):
            #Make sure index is mod n
            indices[i] = indices[i] % n

            #Calculate Key Image and Store for later use
            keyImage = multiply(hash_to_point(multiply(G1,xk[i])), xk[i])
            I[i] = keyImage

            #Store public key for known private key
            Pout[m*indices[i]+i] = multiply(G1, xk[i])
            
            if (indices[i] == (n-1)):
                (left, right) = MLSAG.StartLinkableRing_NoHash(random[m*indices[i]+i], multiply(G1, xk[i]))
            else:
                ck = MLSAG.StartLinkableRing(msgHash, random[m*indices[i]+i], multiply(G1, xk[i]))

                for j in range((indices[i]+1)%n,(n-1)):
                    #Calculate array index for easy reference
                    index = m*j+i
                    
                    #Extract input public key
                    point = Pin[index]

                    #Store public key in output
                    Pout[index] = point

                    #Calculate ring segment
                    ck = MLSAG.CalculateLinkableRingSegment(msgHash, ck, random[index], point, keyImage)

                    #Store s value
                    signature[index+1] = random[index]

                #Calculate last ring segment before c1
                index = m*(n-1) + i

                #Extract Public Key
                point = Pin[index]
                Pout[index] = point

                (left, right) = MLSAG.CalculateLinkableRingSegment_NoHash(ck, random[index], point, keyImage)

                #Store s value
                signature[index+1] = random[index]
                
            #Store update c1 hash
            hasher = add_point_to_hasher(hasher, left)
            hasher = add_point_to_hasher(hasher, right)

        #Store c1
        signature[0] = bytes_to_int(hasher.digest())

        #Calculate 2nd half of each ring
        for i in range(0, m):
            #Fetch c1
            ck = signature[0]

            #Extract Key Image
            keyImage = I[i]

            #Calculate remaining ring segments
            for j in range(0, indices[i]):
                index = m*j+i

                #Extract public key
                point = Pin[index]
                Pout[index] = point

                #Calculate Ring Segment
                ck = MLSAG.CalculateLinkableRingSegment(msgHash, ck, random[index], point, keyImage)

                #Store s value
                signature[index+1] = random[index]

            #Close Ring
            index = m*indices[i] + i
            signature[index+1] = MLSAG.CompleteRing(random[index], ck, xk[i])

        return MLSAG(msgHash, I, Pout, signature)

    #Create Random Numbers before signing
    def Sign_GenRandom(m, msgHash, xk, indices, Pin):
        assert(len(xk) == m)
        assert(len(indices) == m)
        assert( (len(Pin) % m ) == 0)
        n = (len(Pin) // m)
        
        #Create random numbers
        random = []
        for i in range(0, (m*n)):
            random = random + [getRandom()]

        return MLSAG.Sign(m, msgHash, xk, indices, Pin, random)
            
    def Verify(self):
        #Check input parameter lengths
        m = len(self.key_images)
        if (m == 0): return False
        if (len(self.pub_keys) % m != 0): return False
        n = len(self.pub_keys) // m
        if (n == 0): return False
        if (len(self.signature) != (m*n+1)): return False

        #Initialize c1 hasher (total length of array + message hash)
        hasher = sha3.keccak_256()
        hasher.update(int_to_bytes32(4*m+1))
        hasher.update(self.msgHash)

        #Calculate Rings
        for i in range(0, m):
            #Get c1
            ck = self.signature[0]

            #Calculate (n-1) ring segments
            for j in range(0, n-1):
                index = m*j+i
                ck = MLSAG.CalculateLinkableRingSegment(self.msgHash, ck, self.signature[index+1], self.pub_keys[index], self.key_images[i])

            #Calculate last ring segment
            index = m*(n-1)+i
            (left, right) = MLSAG.CalculateLinkableRingSegment_NoHash(ck, self.signature[index+1], self.pub_keys[index], self.key_images[i])

            #Update c1 hash
            hasher = add_point_to_hasher(hasher, left)
            hasher = add_point_to_hasher(hasher, right)
                
        #Check if ring is closed
        ck = bytes_to_int(hasher.digest())
        return (self.signature[0] == ck)

    def Print(self):
        print("MLSAG Signature:")
        print("Dimensions: " + str(len(self.key_images)) + " x " + str(len(self.pub_keys)//len(self.key_images)))
        print("Message Hash: ")
        print(hex(bytes_to_int(self.msgHash)))
        
        print("Key Images:")
        for i in range(0, len(self.key_images)):
            print(hex(CompressPoint(self.key_images[i])))

        print("Pub Keys:")
        for i in range(0, len(self.pub_keys)):
            print(hex(CompressPoint(self.pub_keys[i])))

        print("Signature:")
        for i in range(0, len(self.signature)):
            print(hex(self.signature[i]))

def MSAG_Test(m=4, n=3):
    import random
    xk = []
    indices = []
    pub_keys = []

    #Generate Private Keys
    for i in range(0, m):
        xk = xk + [getRandom()]
        indices = indices + [random.randrange(0, n)]

    #Generate Mix-in Public Keys
    for i in range(0, m*(n-1)):
        P = multiply(G1, getRandom())
        pub_keys = pub_keys + [P]

    msg = b"MSAGTest"
    hasher = sha3.keccak_256()
    hasher.update(msg)
    msgHash = int_to_bytes32(bytes_to_int(hasher.digest()))
    
    msag_signature = MSAG.Sign_GenRandom(m, msgHash, xk, indices, pub_keys)
    msag_signature.Print()

    if (msag_signature.Verify()):
        print("MSAG Verification Success!")
    else:
        print("MSAG Verification Failure!")

def MLSAG_Test(m=4, n=3):
    import random
    xk = []
    indices = []
    pub_keys = []

    #Generate Private Keys
    for i in range(0, m):
        xk = xk + [getRandom()]
        indices = indices + [random.randrange(0, n)]

    #Generate Mix-in Public Keys
    for i in range(0, m*(n-1)):
        P = multiply(G1, getRandom())
        pub_keys = pub_keys + [P]

    msg = b"MLSAGTest"
    hasher = sha3.keccak_256()
    hasher.update(msg)
    msgHash = int_to_bytes32(bytes_to_int(hasher.digest()))
    
    mlsag_signature = MLSAG.Sign_GenRandom(m, msgHash, xk, indices, pub_keys)
    mlsag_signature.Print()

    if (mlsag_signature.Verify()):
        print("MLSAG Verification Success!")
    else:
        print("MLSAG Verification Failure!")




        
        
        
