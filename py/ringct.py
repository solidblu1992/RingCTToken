from ring_signatures import *
from ct import *
from stealth import *

def print_pub_keys(x, m, a, n):
    print("Pub Keys")
    for i in range(0, m-a):
        for j in range(0, n):
            if(not eq(x[j*m+i], NullPoint)):
                print(print_point(CompressPoint(x[j*m+i])))
            else:
                print("0x0")

        print("--")

class RingCT:
    ring_size = 0
    input_count = 0
    input_commitments = []
    output_transactions = []
    mlsag = 0
    redeem_eth_address = 0
    redeem_eth_value = 0
    
    def __init__(self, ring_size, input_count, input_commitments,
                 output_transactions, mlsag,
                 redeem_eth_address=0, redeem_eth_value=0):
        self.ring_size = ring_size
        self.input_count = input_count
        self.input_commitments = input_commitments
        self.output_transactions = output_transactions
        self.mlsag = mlsag
        self.redeem_eth_address = redeem_eth_address
        self.redeem_eth_value = redeem_eth_value

    def Sign(xk, xk_v, xk_bf, mixin_transactions,
             output_transactions, out_v, out_bf,
             redeem_eth_address=0, redeem_eth_value=0):
        import random

        #Check array dimensions
        input_count = len(xk)
        assert(input_count > 0)
        assert(len(xk) == input_count)
        assert(len(xk_v) == input_count)
        assert(len(xk_bf) == input_count)
        assert(redeem_eth_value < (Ncurve // 2))
        
        m = input_count + 1
        assert(len(mixin_transactions) % input_count == 0)
        n = len(mixin_transactions) // input_count + 1

        if (type(output_transactions) != list):
            output_transactions = [output_transactions]
            out_v = [out_v]
            out_bf = [out_bf]
            
        output_count = len(output_transactions)
        assert(output_count > 0)
        assert(len(out_v) == output_count)
        assert(len(out_bf) == output_count)

        #Check that input and output commitment values and blinding factors add up
        in_value = 0
        total_in_bf = 0
        out_value = 0
        total_out_bf = 0
        z = 0
        for i in range(0, input_count):
            in_value = in_value + xk_v[i]
            total_in_bf = (total_in_bf + xk_bf[i]) % Ncurve

        for i in range(0, output_count):
            out_value = out_value + out_v[i]
            total_out_bf = (total_out_bf + out_bf[i]) % Ncurve

        z = (total_in_bf + Ncurve - total_out_bf) % Ncurve

        #Add redeemed token value to out_value, only used in withdrawal signatures
        out_value = out_value + redeem_eth_value;

        assert(in_value == out_value)
        assert(z != 0) #blinding factors must add to a non-zero otherwise privacy is erased!

        #Pick slot for key vector
        indices = [random.randrange(0, n)] * m
        pub_keys = [NullPoint] * (m*n)
        input_commitments_new = [NullPoint]*((m-1)*n)
        priv_keys = [0] * (m)

        #Fill in existing public / private keys and commitments
        for i in range(0, m-1):
            priv_keys[i] = xk[i]
            
            for j in range(0, n):
                if (j == indices[0]):
                    pub_keys[j*m+i] = multiply(G1, xk[i])
                    input_commitments_new[j*(m-1)+i] = add(multiply(H, xk_v[i]), multiply(G1, xk_bf[i]))
                elif(j > indices[0]):
                    pub_keys[j*m+i] = mixin_transactions[(j-1)*(m-1)+i].pub_key
                    input_commitments_new[j*(m-1)+i] = mixin_transactions[(j-1)*(m-1)+i].c_value
                else:
                    pub_keys[j*m+i] = mixin_transactions[j*(m-1)+i].pub_key
                    input_commitments_new[j*(m-1)+i] = mixin_transactions[j*(m-1)+i].c_value

        #Start building signature massage over output public keys, committed values, dhe points, and encrypted messages (both message and iv)
        #Hash output transactions
        msgHash = int_to_bytes32(output_count)

        for i in range(0, output_count):
            #Continue hash chain
            hasher = sha3.keccak_256(msgHash)

            #Hash pub keys, values, dhe points, and encrypted data
            hasher = add_point_to_hasher(hasher, output_transactions[i].pub_key)

            assert(eq(add(multiply(H, out_v[i]), multiply(G1, out_bf[i])), output_transactions[i].c_value))
            hasher = add_point_to_hasher(hasher, output_transactions[i].c_value)

            hasher = add_point_to_hasher(hasher, output_transactions[i].dhe_point)

            hasher.update(output_transactions[i].pc_encrypted_data.message)
            hasher.update(int_to_bytes32(bytes_to_int(output_transactions[i].pc_encrypted_data.iv)))

            #Compute new digest
            msgHash = hasher.digest()

        #Hash ETH redeem address and value if they are used
        if (redeem_eth_value > 0):
            #Continue hash chain
            hasher = sha3.keccak_256(msgHash)

            #Hash redeem address and value
            hasher.update(int_to_bytes20(redeem_eth_address))
            hasher.update(int_to_bytes32(redeem_eth_value))

            #Compute new digest
            msgHash = hasher.digest()
        
        neg_total_out_commitment = neg(add(multiply(H, in_value), multiply(G1, total_out_bf)))
        
        #Sum up last column
        for j in range(0, n):
            #Subtract output commitments
            s_point = neg_total_out_commitment
            for i in range(0, m-1):
                #add public key
                s_point = add(s_point, pub_keys[j*m+i])
                s_point = add(s_point, input_commitments_new[j*(m-1)+i])

            #Store last column of public keys
            pub_keys[j*m+(m-1)] = s_point                

        #Determine private key for last column
        priv_keys[m-1] = z
        for i in range(0, m-1):
            priv_keys[m-1] = (priv_keys[m-1] + xk[i]) % Ncurve

        return( RingCT(n, m-1,
                       input_commitments_new,
                       output_transactions,
                       MLSAG.Sign_GenRandom(m, msgHash, priv_keys, indices, pub_keys),
                       redeem_eth_address, redeem_eth_value))

    def Verify(self):
        #Assert array lengths
        if(self.input_count <= 0): return False
        output_count = len(self.output_transactions)
        if(output_count <= 0): return False
        if(self.redeem_eth_value >= (Ncurve // 2)): return False
        
        n = self.ring_size
        m = self.input_count+1
        if(len(self.input_commitments) != n*(m-1)): return False        
        
        #Sum output commitments
        neg_total_output_commitment = NullPoint
        for i in range(0, len(self.output_transactions)):
            neg_total_output_commitment = add(neg_total_output_commitment, self.output_transactions[i].c_value)

        #Add redeem commitment for withdrawal
        if (self.redeem_eth_value > 0):
            neg_total_output_commitment  = add(neg_total_output_commitment, multiply(H, self.redeem_eth_value))

        #negate it
        neg_total_output_commitment = neg(neg_total_output_commitment)

        #Verify that signature was built right
        for j in range(0, n):
            s_point = neg_total_output_commitment
            
            for i in range(0, m-1):
                s_point = add(s_point, self.mlsag.pub_keys[j*m+i])
                s_point = add(s_point, self.input_commitments[j*(m-1)+i])

            if (not eq(s_point, self.mlsag.pub_keys[j*m+(m-1)])): return False

        #Verify hash of output transactions: public keys, committed values, dhe_points, and encrypted data (message and iv)
        #Hash output transactions
        msgHash = int_to_bytes32(output_count)

        for i in range(0, output_count):
            #Continue hash chain
            hasher = sha3.keccak_256(msgHash)

            #Hash pub keys, values, dhe points, and encrypted data
            hasher = add_point_to_hasher(hasher, self.output_transactions[i].pub_key)            
            hasher = add_point_to_hasher(hasher, self.output_transactions[i].c_value)            
            hasher = add_point_to_hasher(hasher, self.output_transactions[i].dhe_point)

            hasher.update(self.output_transactions[i].pc_encrypted_data.message)
            hasher.update(int_to_bytes32(bytes_to_int(self.output_transactions[i].pc_encrypted_data.iv)))

            #Compute new digest
            msgHash = hasher.digest()

        #Hash ETH redeem address and value if they are used
        if (self.redeem_eth_value > 0):
            #Continue hash chain
            hasher = sha3.keccak_256(msgHash)

            #Hash redeem address and value
            hasher.update(int_to_bytes20(self.redeem_eth_address))
            hasher.update(int_to_bytes32(self.redeem_eth_value))

            #Compute new digest
            msgHash = hasher.digest()

        msgHash = hasher.digest()        
        if (msgHash != self.mlsag.msgHash): return False

        #Verify signature
        return self.mlsag.Verify()

    def Serialize(self):
        out = [self.redeem_eth_address, self.redeem_eth_value]

        m = len(self.mlsag.key_images)
        assert(len(self.mlsag.pub_keys) % m == 0)
        n = len(self.mlsag.pub_keys) // m

        out += [n*(m-1), len(self.output_transactions), len(self.mlsag.key_images)*2, len(self.mlsag.signature)]

        #Print input utxos (public key only, committed values will be supplied by the contract)
        for j in range(0, n):
            for i in range(0, m-1):
                point = normalize(self.mlsag.pub_keys[j*m+i])
                out += [point[0], point[1]]
        
        #Print output utxos (public key, dhe_point, committed value, and encrypted data)
        for i in range(0, len(self.output_transactions)):
            point = normalize(self.output_transactions[i].pub_key)
            out += [point[0], point[1]]

            point = normalize(self.output_transactions[i].c_value)
            out += [point[0], point[1]]

            point = normalize(self.output_transactions[i].dhe_point)
            out += [point[0], point[1]]

            out += [bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[:32]),
                    bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[32:]),
                    bytes_to_int(self.output_transactions[i].pc_encrypted_data.iv)]

        #Print key images
        for i in range(0, m):
            point = normalize(self.mlsag.key_images[i])
            out += [point[0], point[1]]

        #Print signature (c1, s1, s2, ... snm)
        for i in range(0, len(self.mlsag.signature)):
            out += [self.mlsag.signature[i]]

        return tuple(out)

    def Print(self):
        print("Ring CT Transaction")
        print("Inputs (PubKey1, C_Value1), ..., (PubKeyM, C_ValueM), {sum(PubKey1...M-1) + sum(C_Value1...M-1) - sum(C_Value_Out)}:")
        
        for j in range(0, self.ring_size):
            print("Key Vector " + str(j+1))
            
            for i in range(0, self.input_count+1):
                print(bytes_to_str(CompressPoint(self.mlsag.pub_keys[j*(self.input_count+1)+i])), end="")

                if (i < self.input_count):
                    print(", " + bytes_to_str(CompressPoint(self.input_commitments[j*(self.input_count) + i])))
                else:
                    print()

        print("-----")
        print("Outputs (PubKeyK, C_Value_OutK)")
        for i in range(0, len(self.output_transactions)):
            print("Output " + str(i+1))
            print(bytes_to_str(CompressPoint(self.output_transactions[i].pub_key)) + ", " + bytes_to_str(CompressPoint(self.output_transactions[i].c_value)))

        if (self.redeem_eth_value > 0):
            print("-----")
            print("Redeemed ETH Address: " + hex(self.redeem_eth_address))
            print("Redeemed ETH Value: " + str(self.redeem_eth_value) + " wei or " + str(self.redeem_eth_value / 10**18) + " ETH")

    def Print_MEW(self):
        output_count = len(self.output_transactions)

        print("Ring CT MEW Representation - for use with Send():")
        print("argsSerialized:")

        #Print redeem eth parameters (will both be 0 in non-withdrawal tx)
        print(hex(self.redeem_eth_address) + ",")
        print(str(self.redeem_eth_value) + ",")

        #Print array lengths
        m = len(self.mlsag.key_images)
        assert(len(self.mlsag.pub_keys) % m == 0)
        n = len(self.mlsag.pub_keys) // m
        
        print(str(n*(m-1)) + ", ", end="")
        print(str(len(self.output_transactions)) + ", ", end="")
        print(str(len(self.mlsag.key_images)*2) + ", ", end="")
        print(str(len(self.mlsag.signature)) + ",")

        #Print input utxos (public key only, committed values will be supplied by the contract)
        for j in range(0, n):
            for i in range(0, m-1):                    
                print(point_to_str(self.mlsag.pub_keys[j*m+i]) + ",")
        
        #Print output utxos (public key, dhe_point, committed value, and encrypted data)
        for i in range(0, len(self.output_transactions)):
            print(point_to_str(self.output_transactions[i].pub_key) + ",")
            print(point_to_str(self.output_transactions[i].c_value) + ",")
            print(point_to_str(self.output_transactions[i].dhe_point) + ",")
            print(bytes_to_str(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[:32])) + ",")
            print(bytes_to_str(bytes_to_int(self.output_transactions[i].pc_encrypted_data.message[32:])) + ",")
            print(bytes_to_str(bytes_to_int(self.output_transactions[i].pc_encrypted_data.iv)) + ",")

        #Print key images
        for i in range(0, m):
            print(point_to_str(self.mlsag.key_images[i]) + ",")

        #Print signature (c1, s1, s2, ... snm)
        for i in range(0, len(self.mlsag.signature)):
            if (i > 0):
                print(",")
            print(bytes_to_str(self.mlsag.signature[i]), end="")

def RingCTTest(input_count = 2, mixin_count = 3, outputs = 2, rngSeed=0):
    import random
    print()
    print("================================")
    print("Running RingCT Test (Repeatable)")
    print("input_count = " + str(input_count))
    print("mixin_count = " + str(mixin_count))
    print("ring_size = " + str(input_count+1) + " x " + str(mixin_count+1))
    print("================================")

    #Store View and Spend Keys
    pri_viewkey  = 0x26748d27140087af35b5523fbf4063a48e10277b7bb67379eae64b1e9bcdd49c
    pri_spendkey = 0x0657e10b4ecf56e94546357f35447ec39f6fee66c44c013aa55b54fcd6e4c340
    pub_viewkey  = multiply(G1, pri_viewkey)
    pub_spendkey = multiply(G1, pri_spendkey)

    #Pre-fetch random values for repeatable results
    r_index = 0
    r = []
    if (rngSeed==0):
        random.seed()
    else:
        random.seed(rngSeed)
        
    for i in range(0, 100):
        r = r + [getRandomUnsafe()]

    #Store Committed Values (each 0.01 ETH)
    xk_v = [1 * (10**16)] * (input_count*(mixin_count+1))
    xk_v_total = (1 * (10**16)) * (input_count)
    xk_bf = [0] * len(xk_v)
    
    #for i in range(0, len(xk_v)):
    #	xk_bf = xk_bf + [r[r_index]]
    #	r_index = r_index + 1

    #Store Owned Input Wallets (Both owned and mixin)
    stealth_tx = []
    
    for i in range (0, len(xk_v)):
        stealth_tx = stealth_tx + [StealthTransaction.Generate(pub_viewkey, pub_spendkey, xk_v[i], xk_bf[i], r[r_index])]
        r_index = r_index + 1

    #Create Deposits (Both for input TX and mixin TX)
    print("Create Deposits:")
    for i in range(0, len(stealth_tx)):
        if (i < input_count):
            print("Input TX " + str(i) + ":\t[priv key: " + hex(stealth_tx[i].GetPrivKey(pri_viewkey, pri_spendkey)) + "]")
        else:
            print("Mixin TX " + str(i - input_count) + ":")
            
        print("Pub Key:\t" + print_point(CompressPoint(stealth_tx[i].pub_key)))
        print("DHE Point:\t" + print_point(CompressPoint(stealth_tx[i].dhe_point)))
        print("Value:\t\t" + str(xk_v[i] / (10**18)) + " ETH (" + str(xk_v[i]) + " wei)")
        print("BF:\t\t" + hex(xk_bf[i]))



        print()

    print("================================")

    #Create Output Addresses (sent to self via stealth address)
    import math
    stealth_tx_out = []
    stealth_tx_out_v = []
    stealth_tx_out_bf = []
    rp_out = []
    bf_total = 0
    bf_target = r[r_index]
    r_index = r_index+1
    
    for i in range(0, outputs):
        if (i < (outputs-1)):
            v = xk_v_total // outputs
            bf = r[r_index]
            rand = r[r_index+1]
            r_index = r_index + 2
            
        else:
            v = (xk_v_total - (xk_v_total // outputs)*i)
            bf = (Ncurve-bf_target-bf_total) % Ncurve
            rand = r[r_index]
            r_index = r_index + 1
            
        stealth_tx_out = stealth_tx_out + [StealthTransaction.Generate(pub_viewkey, pub_spendkey, v, bf, rand)]
        stealth_tx_out_v = stealth_tx_out_v + [v]
        stealth_tx_out_bf = stealth_tx_out_bf + [bf]
        bf_total = (bf_total + bf) % Ncurve
            
        print("Output TX " + str(i) + ":")
        print("Pub Key:\t" + print_point(CompressPoint(stealth_tx_out[i].pub_key)))
        print("DHE Point:\t" + print_point(CompressPoint(stealth_tx_out[i].dhe_point)))
        print("Value:\t\t" + str(v / 10**18) + " ETH (" + str(v) + " wei)")
        print("BF:\t\t" + hex(bf))
        print()

        #Create Pedersen Commitments
        pow10 = math.floor(math.log(v,10))
        val = v // 10**pow10
        rem = v - ( (val) * (10**pow10))
        bits = math.floor(math.log(val,4))+1
        
        #print("v: " + str(val) + ", pow10: " + str(pow10) + ", rem: " + str(rem))
        rp_out = rp_out + [PCRangeProof.Generate(val, pow10, rem, 2, bf)]
        
    #Retreive Private Keys for Input Transactions
    rct_xk = []
    for i in range(0, input_count):
        rct_xk = rct_xk + [stealth_tx[i].GetPrivKey(pri_viewkey, pri_spendkey)]

    rct_xk_v = xk_v[:input_count]
    rct_xk_bf = xk_bf[:input_count]
    rct_mixin_tx = stealth_tx[input_count:]

    #Print Input data for MyEtherWallet
    print()
    print("================================")
    print("MyEtherWallet Vectors")
    print("================================")
    print("Create Deposits (MEW):")
    print("value = " + str(xk_v_total))
    print("dest_pub_keys:")
    for i in range(0, len(stealth_tx)):
        if i > 0:
            print(",")
        print(print_point(CompressPoint(stealth_tx[i].pub_key)),end="")
    print("\n")

    print("dhe_points:")
    for i in range(0, len(stealth_tx)):
        if i > 0:
            print(",")
        print(print_point(CompressPoint(stealth_tx[i].dhe_point)),end="")
    print("\n")

    print("values:")
    for i in range(0, len(stealth_tx)):
        if i > 0:
            print(",")
        print(str(xk_v[i]),end="")
    print("\n")

    print("================================")
    print("Prove Ranges (MEW):")
    for i in range(0, len(rp_out)):
        rp_out[i].Print_MEW()
        print()

    print("================================")
    print("RingCT Send (MEW):")
    rct = RingCT.Sign(rct_xk, rct_xk_v, rct_xk_bf, rct_mixin_tx, stealth_tx_out, stealth_tx_out_v, stealth_tx_out_bf)
    rct.Print_MEW()

    print("================================")
    print("RingCT Withdraw (MEW):")
    return rct
