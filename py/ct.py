from ring_signatures import *

class PCRangeProof:
    total_commit = NullPoint
    power10 = 0
    offset = 0
    value = 0
    bf = 0
    range_proof = 0
    
    def __init__(self, total_commit, power10, offset, value, bf, range_proof):
        self.total_commit = total_commit
        self.power10 = power10
        self.offset = offset
        self.value = value
        self.range_proof = range_proof

    def GetTotalCommitment(self):
        return ExpandPoint(bytes_to_int(self.range_proof.msgHash))

    def GenerateParameters(total_value, target_bits=1):
        import math

        if (total_value == 0):
            return(0, 17, 0, target_bits)
        else:
            bits = 0
            i = 0
            while(bits < target_bits):
                power10 = math.floor(math.log(total_value,10)) - i
                val = total_value // 10**power10
                bits = math.floor(math.log(val,4))+1
                i = i + 1
                
            rem = total_value - ( (val) * (10**power10))
            
            return (val, power10, rem, bits)

    def Commit(value, blinding_factor):
        point = shamir([G1, H], [blinding_factor, value])
            
        return point

    def Generate(value, power10, offset, bits_override, total_blinding_factor):
        #Figure out how many bits value is in base 4
        import math

        if (value == 0):
            bits = bits_override
        else:
            bits = math.floor(math.log(value,4))+1

        if (bits_override > bits):
            bits = bits_override

        c = []
        cp = []
        cpp = []
        cppp = []
        keys = []
        indices = []
        commitments = []
        bfTotal = 0
        for i in range(0, bits):
            v = (value & (3 << (2*i))) >> (2*i)

            if i < (bits-1):
                bf = getRandom()
                bfTotal = bfTotal + bf
            else:
                bf = (total_blinding_factor - bfTotal) % Ncurve

            keys = keys + [bf]
            indices = indices + [v]
                
                
            p1 = PCRangeProof.Commit(v * (4**i), bf)
            p2 = neg(multiply(H, 4**i))
            
            c = c + [p1]            
            p1 = add(p1, p2)
            cp = cp + [p1]
            p1 = add(p1, p2)
            cpp = cpp + [p1]
            p1 = add(p1, p2)
            cppp = cppp + [p1]


        commitments = c + cp + cpp + cppp
        total_commit = PCRangeProof.Commit(value, total_blinding_factor)
        range_proof = MSAG.Sign_GenRandom(bits, int_to_bytes32(CompressPoint(total_commit)), keys, indices, commitments)

        if (power10 > 0):
            total_commit = multiply(total_commit, 10**power10)
            total_blinding_factor = (total_blinding_factor * (10**power10)) % Ncurve
            value = value * (10**power10)

        if (offset > 0):
            total_commit = add(total_commit, multiply(H, offset))
            value = value + offset
            
        return PCRangeProof(total_commit, power10, offset, value, bf, range_proof)
            

    def Verify(self):
        L = len(self.range_proof.pub_keys)
        if (L % 4 != 0): return False
        L = L // 4
        
        #Check that bitwise commitments add up
        point = NullPoint
        for i in range(0, L):
            point = add(point, self.range_proof.pub_keys[i])
        
        if (not eq(point, self.GetTotalCommitment())): return False

        #Check that counter commitments are OK
        for i in range(0, L):
            point = self.range_proof.pub_keys[i]
            subtract = neg(multiply(H, 4**i))

            for j in range(1, 4):
                point = add(point, subtract)
                if (not eq(point, self.range_proof.pub_keys[j*L + i])): return False
                        
        return self.range_proof.Verify()

    def Print(self):
        L = len(self.range_proof.pub_keys) // 4
        
        print("Committed Value = " + hex(CompressPoint(self.GetTotalCommitment())))
        print("Possible Range = " + str(self.offset) + " to " + str((4**L-1)*(10**self.power10)+self.offset))
        print("Possible # of Values = " + str(4**L-1))
        print("Range Proof:")
        self.range_proof.Print()
        

    #Prints range proof in a format to be verified on the Ethereum blockchain
    def Print_MEW(self):
        commitment = self.GetTotalCommitment()
        L = len(self.range_proof.pub_keys) // 2

        print()
        print("Borromean Range Proof MEW Representation - for use with VerifyBorromeanRangeProof():")
        print("argsSerialized:")
        print(point_to_str(commitment) + ",")

        combined = L & 0xFFFFFFFFFFFFFFFF
        combined |= (len(self.range_proof.signature) & 0xFFFFFFFFFFFFFFFF) << 64
        print(bytes_to_str(combined) + ",")

        for i in range(0, L // 2):
            print(point_to_str(self.range_proof.pub_keys[i]) + ",")

        for i in range(0, len(self.range_proof.signature)):
            if (i > 0):
                print(",")
                
            print(bytes_to_str(self.range_proof.signature[i]), end="")

        print("\n")
        print("power10:")
        print(str(self.power10))

        print()
        print("offset:")
        print(str(self.offset))
        
class PCAESMessage:
    message = b""
    iv = b""

    def __init__(self, message, iv):
        self.message = message
        self.iv = iv
        
    def Encrypt(value, blinding_factor, shared_secret):
        from Crypto.Cipher import AES
        from Crypto import Random
        key = int_to_bytes32(shared_secret)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        message = cipher.encrypt(int_to_bytes32(value) + int_to_bytes32(blinding_factor))
        
        return PCAESMessage(message, iv)

    def Decrypt(self, shared_secret):
        from Crypto.Cipher import AES
        from Crypto import Random
        key = int_to_bytes32(shared_secret)
        cipher = AES.new(key, AES.MODE_CFB, self.iv)
        msg = cipher.decrypt(self.message)

        value = bytes_to_int(msg[:32])
        bf = bytes_to_int(msg[32:])

        return (value, bf)

    def to_scalars(self):
        from Crypto import Random
        rand = Random.new();
        return [bytes_to_int(rand.read(1) + self.message[:31]) % Ncurve,
                bytes_to_int(rand.read(1) + self.message[31:62]) % Ncurve,
                bytes_to_int(rand.read(14) + self.message[62:] + self.iv) % Ncurve]

    def from_scalars(s):
        assert(len(s) == 3)
        message = int_to_bytes32(s[0])[2:] + int_to_bytes32(s[1])[2:] + int_to_bytes32(s[2])[14:16]
        iv = int_to_bytes32(s[2])[16:]
        
        return PCAESMessage(message, iv)
        
    def Print(self):
        print("Encrypted Message: " + bytes32_to_str(bytes_to_int(self.message[:32])) + bytes32_to_str(bytes_to_int(self.message[32:]))[30:])
        print("iv: " + bytes16_to_str(bytes_to_int(self.iv)))

def RangeProofTest(value=48, pow10=18, bits=0, offset=1000000, bf=getRandom()):    
    print("Generating a min " + str(bits) + "-bit Range Proof for " + str(value) + "x(10**" + str(pow10) + ")+" + str(offset) + " = " + str(value*(10**pow10)+offset))
    print("Blinding factor = " + hex(bf))
    rp = PCRangeProof.Generate(value, pow10, offset, bits, getRandom())
    rp.Print()

    print("\nVerifing Range proof...", end="")
    if(rp.Verify()):
        print("Success!")
    else:
        print("Failure!")

    rp.Print_MEW()
    return rp

def AESTest(value=48, pow10=18, offset=1000000,bf=getRandom()):
    v = value*(10**pow10)+offset
    print("Hiding " + str(v) + " and blinding factor " + hex(bf))
    shared_secret = hash_of_point(multiply(G1, getRandom()))
    msg = PCAESMessage.Encrypt(v, bf, shared_secret)
    msg.Print()

    (v2, bf2) = msg.Decrypt(shared_secret)
    print("Recovered " + str(v2) + " and blinding factor " + hex(bf2))

    
    
