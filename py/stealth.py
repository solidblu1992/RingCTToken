from ct import *

class StealthTransaction:
    pub_key = 0
    dhe_point = 0
    c_value = 0
    pc_encrypted_data = 0
    
    def __init__(self, pub_key=0, dhe_point=0, c_value=0, pc_encrypted_data=0):
        self.pub_key = pub_key
        self.dhe_point = dhe_point
        self.pc_encrypted_data = pc_encrypted_data
        self.c_value = c_value

    def isEncrypted(self):
        if (type(self.c_value) == tuple):
            return True
        else:
            return False

    def Generate(pubViewKey, pubSpendKey, value, blinding_factor, r):
        R = multiply(G1, r)

        ss1 = hash_of_point(multiply(pubViewKey, r)) % Ncurve
        dest_pub_key = add(multiply(G1, ss1), pubSpendKey)

        ss2 = hash_of_point(multiply(pubSpendKey, r))
        encrypted_message = PCAESMessage.Encrypt(value, blinding_factor, ss2)

        c_value = add(multiply(H, value), multiply(G1, blinding_factor))

        return StealthTransaction(dest_pub_key, R, c_value, encrypted_message)


    def Generate_GenRandom(pubViewKey, pubSpendKey, value, blinding_factor):
        r = getRandom()
        return StealthTransaction.Generate(pubViewKey, pubSpendKey, value, blinding_factor, r)

    def CheckOwnership(self, privViewKey, pubSpendKey):
        ss = hash_of_point(multiply(self.dhe_point, privViewKey)) % Ncurve
        pub_key = add(multiply(G1, ss), pubSpendKey)

        if (eq(self.pub_key, pub_key)):
            return True
        else:
            return False

    def GetPrivKey(self, privViewKey, privSpendKey):
        ss = hash_of_point(multiply(self.dhe_point, privViewKey)) % Ncurve
        
        priv_key = (ss + privSpendKey) % Ncurve
        return priv_key
        
    def DecryptData(self, privSpendKey):
        if (self.isEncrypted()):
            ss = hash_of_point(multiply(self.dhe_point, privSpendKey))
            return (self.pc_encrypted_data.Decrypt(ss))
        else:
            return(self.c_value, 0)

    def Print(self):
        #print("Stealth Transaction:")
        if (type(self.pub_key) == tuple):
            print("Public Key: " + bytes32_to_str(CompressPoint(self.pub_key)))

        if (type(self.dhe_point) == tuple):
            print("DHE Point: " + bytes32_to_str(CompressPoint(self.dhe_point)))

        if (type(self.c_value) == tuple):
            print("C_Value: " + bytes32_to_str(CompressPoint(self.c_value)))
        elif (type(self.c_value) == int):
            print("Value: " + str(self.c_value))

        if (type(self.pc_encrypted_data) == PCAESMessage):
            self.pc_encrypted_data.Print()

    def PrintScalars(self):
        if (type(self.pc_encrypted_data) != int):
            s = self.pc_encrypted_data.to_scalars()
            for i in range(0, len(s)):
                print("s[" + str(i) + "]: " + hex(s[i]))
    
def StealthTxTest():
    MyPrivateViewKey = getRandom()
    MyPublicViewKey = multiply(G1, MyPrivateViewKey)
    
    MyPrivateSpendKey = getRandom()
    MyPublicSpendKey = multiply(G1, MyPrivateSpendKey)
    print("Generating Stealth Address: ")
    print("Public View Key: " + print_point(CompressPoint(MyPublicViewKey)))
    print("Public Spend Key: " + print_point(CompressPoint(MyPublicSpendKey)))


    print("\nGenerating ", end="")
    stx = StealthTransaction.Generate(MyPublicViewKey, MyPublicSpendKey, 5*(10**18), getRandom())
    stx.Print()

    print("\nChecking Ownership...", end="")
    if (stx.CheckOwnership(MyPrivateViewKey, MyPublicSpendKey)):
        print("Success!")
    else:
        print("Failure!")

    print("Private Key: " + hex(stx.GetPrivKey(MyPrivateViewKey, MyPrivateSpendKey)))

    (v, bf) = stx.DecryptData(MyPrivateSpendKey)
    print("Decrypted Value: " + str(v))
    print("Decrypted Blinding Factor: " + hex(bf))

    print("")
    stx.PrintScalars()

    print("\nFrom Scalars:")
    s = stx.pc_encrypted_data.to_scalars()
    pc = PCAESMessage.from_scalars(s)
    pc.Print()
