from ring_signatures import *
from ct import *
from stealth import *
from ringct import *

class RingCTToken:
    MyPrivateViewKey = 0
    MyPublicViewKey = (FQ(0), FQ(0))
    
    MyPrivateSpendKey = 0
    MyPublicSpendKey = (FQ(0), FQ(0))

    MyUTXOPool = []
    MyPendingUTXOPool = []
    MixinTxPool = []

    debugPrintingEnabled = False

    #def __init__(self):

    def GenerateNewStealthAddress(self):
        self.MyPrivateViewKey = getRandom()
        self.MyPrivateSpendKey = getRandom()

        self.MyPublicViewKey = multiply(G1, self.MyPrivateViewKey)
        self.MyPublicSpendKey = multiply(G1, self.MyPrivateSpendKey)

        if (self.debugPrintingEnabled):
            print()
            print("New Stealth Address Generated:")
            print("Public View Key:\t" + print_point(CompressPoint(self.MyPublicViewKey)))
            print("Public Spend Key:\t" + print_point(CompressPoint(self.MyPublicSpendKey)))

        return [self.MyPublicViewKey, self.MyPublicSpendKey]

    def SetStealthAddress(self, privViewKey, privSpendKey):
        self.MyPrivateViewKey = privViewKey
        self.MyPrivateSpendKey = privSpendKey

        self.MyPublicViewKey = multiply(G1, self.MyPrivateViewKey)
        self.MyPublicSpendKey = multiply(G1, self.MyPrivateSpendKey)

        if (self.debugPrintingEnabled):
            print()
            print("New Stealth Address Assigned:")
            print("Public View Key:\t" + print_point(CompressPoint(self.MyPublicViewKey)))
            print("Public Spend Key:\t" + print_point(CompressPoint(self.MyPublicSpendKey)))

        return [self.MyPublicViewKey, self.MyPublicSpendKey]

    def GetUTXOPrivKey(self, index):
        return(self.MyUTXOPool[index].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey))

    def DecryptUTXO(self, index):
        return(self.MyUTXOPool[index].DecryptData(self.MyPrivateSpendKey))

    def GenerateUTXOs(self, v, bf, pub_viewkey=None, pub_spendkey=None):
        if (type(v) != list):
            v = [v]
        if (type(bf) != list):
            bf = [bf]
        assert(len(v) == len(bf))

        count = len(v)

        if (self.debugPrintingEnabled):
            print()
            print("New Unspend Tx Outputs (" + str(count) + ") Generated:")

        for i in range(0, count):
            r = getRandom()
            if (pub_viewkey == None or pub_spendkey == None):
                stealth_tx = StealthTransaction.Generate(self.MyPublicViewKey, self.MyPublicSpendKey, v[i], bf[i], r)
                self.MyUTXOPool = self.MyUTXOPool + [stealth_tx]
                mine = True
            else:
                stealth_tx = StealthTransaction.Generate(pub_viewkey, pub_spendkey, v[i], bf[i], r)
                self.MixinTxPool = self.MixinTxPool + [stealth_tx]
                mine = False

            if (self.debugPrintingEnabled):
                print("UTXO " + str(len(self.MyUTXOPool)-1) + ":")
                    
                if (mine and self.debugPrintingEnabled):
                    print("[priv key: " + hex(self.MyUTXOPool[-1].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)) + "]")
                    print("[value: " + str(v[i]) + "]")
                    print("[bf: " + hex(bf[i]) + "]")

                stealth_tx.Print()
                print()

    def GeneratePendingUTXOs(self, v, bf, pub_viewkey=None, pub_spendkey=None):
        if (type(v) != list):
            v = [v]
        if (type(bf) != list):
            bf = [bf]
        assert(len(v) == len(bf))

        count = len(v)

        if (self.debugPrintingEnabled):
            print()
            print("New Pending Unspend Tx Outputs (" + str(count) + ") Generated:")

        for i in range(0, count):
            r = getRandom()
            if (pub_viewkey == None or pub_spendkey == None):
                stealth_tx = StealthTransaction.Generate(self.MyPublicViewKey, self.MyPublicSpendKey, v[i], bf[i], r)
                self.MyPendingUTXOPool = self.MyPendingUTXOPool + [stealth_tx]
                mine = True
            else:
                stealth_tx = StealthTransaction.Generate(pub_viewkey, pub_spendkey, v[i], bf[i], r)
                self.MixinTxPool = self.MixinTxPool + [stealth_tx]
                mine = False

            if (self.debugPrintingEnabled):
                print("UTXO " + str(len(self.MyPendingUTXOPool)-1) + ":")
                    
                if (mine and self.debugPrintingEnabled):
                    print("[priv key: " + hex(self.MyPendingUTXOPool[-1].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)) + "]")
                    print("[value: " + str(v[i]) + "]")
                    print("[bf: " + hex(bf[i]) + "]")

                stealth_tx.Print()
                print()
            
    def GenerateMixinAddresses(self, count=1):        
        if (self.debugPrintingEnabled):
            print("\nNew Mixin Transactions (" + str(count) + ") Generated:")
        
        for i in range(0, len(count)):
            stealth_tx = StealthTransaction(multiply(G1, getRandom()), multiply(G1, getRandom()), multiply(G1, 1*10**14), PCAESMessage.Encrypt(getRandom(), getRandom(), getRandom()))
                
            self.MixinTxPool = self.MixinTxPool + [stealth_tx]

            if(self.debugPrintingEnabled):
                print("TX " + str(len(self.MixinTxPool)-1) + ":")
                stealth_tx.Print()
                print()

    def MarkUTXOAsSpent(self, indices):
        if (type(indices) != list):
            indices = [indices]

        index = 0
        for i in range(0, len(indices)):
            index = indices[i]-i
            self.MixinTxPool = self.MixinTxPool + [self.MyUTXOPool[index]]
            self.MyUTXOPool = self.MyUTXOPool[:index] + self.MyUTXOPool[index+1:]

            if(self.debugPrintingEnabled):
                print("Mixin Tx " + str(len(self.MixinTxPool)+1) + " Created from UTXO " + str(indices[i]))

        if(self.debugPrintingEnabled):
            print("New Mixin Tx count: " + str(len(self.MixinTxPool)))
            print("New total UTXO count: " + str(len(self.MyUTXOPool)))
            print()

    def MintPendingUTXOs(self, indices):
        if (type(indices) != list):
            indices = [indices]

        index = 0
        for i in range(0, len(indices)):
            index = indices[i]-i
            self.MyUTXOPool = self.MyUTXOPool + [self.MyPendingUTXOPool[index]]
            self.MyPendingUTXOPool = self.MyPendingUTXOPool[:index] + self.MyPendingUTXOPool[index+1:]

            if(self.debugPrintingEnabled):
                print("UTXO " + str(len(self.MyUTXOPool)+1) + " Created from Pending UTXO " + str(indices[i]))

        if(self.debugPrintingEnabled):
            print("New total UTXO count: " + str(len(self.MyUTXOPool)))
            print("New total pending UTXO count: " + str(len(self.MyPendingUTXOPool)))
            print()

    #Import Tx's from Array
    #Returns owned=True if Tx belongs to Stealth Address
    #Returns duplicate=True if Tx already exists in UTXO Pool
    def AddTx(self, tx):
        duplicate = False
        owned = tx.CheckOwnership(self.MyPrivateViewKey, self.MyPublicSpendKey)

        #Check both UTXO and Mixin Pools for duplicate transactions
        if (owned):
            for i in range(0, len(self.MyUTXOPool)):
                if (CompressPoint(self.MyUTXOPool[i].pub_key) == CompressPoint(tx.pub_key)):
                    duplicate = True
                    
        for i in range(0, len(self.MixinTxPool)):
                if (CompressPoint(self.MixinTxPool[i].pub_key) == CompressPoint(tx.pub_key)):
                    duplicate = True

        #If not duplicate, add TX to relevant pool
        if (not duplicate):
            if (owned):
                self.MyUTXOPool = self.MyUTXOPool + [tx]
            else:
                self.MixinTxPool = self.MixinTxPool + [tx]                

        return (owned, duplicate)

    #Generate Send Tx
    def GenerateSendTx(self, UTXOindices, mixins=2, output_values=None, pubViewKeys=None, pubSpendKeys=None):
        UTXOindices = list(set(UTXOindices)) #remove duplicates
        mixin_count = len(UTXOindices)*mixins
        assert((len(self.MixinTxPool)+len(self.MyUTXOPool)-len(UTXOindices)) >= mixin_count) #Must have enough mixin transactions to perform Tx

        print("Generating Spend Tx...")

        #Get Private Keys, values, and blinding factors from UTXO set
        in_utxos = []
        in_values = [0] * len(UTXOindices)
        in_bfs = [0] * len(UTXOindices)
        in_xk = [0] * len(UTXOindices)
        for i in range(0, len(UTXOindices)):
            in_utxos = in_utxos + [self.MyUTXOPool[UTXOindices[i]]]
            
            if (in_utxos[i].isEncrypted()):
                (in_values[i], in_bfs[i]) = in_utxos[i].DecryptData(self.MyPrivateSpendKey)
            else:
                (in_values[i], in_bfs[i]) = (in_utxos[i].c_value, 0)
                
            in_xk[i] = in_utxos[i].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)

        #Pick random mixin transactions from spent utxos, unknown utxos, and unspent utxos
        rem_utxo_indices = list(set(range(0, len(self.MyUTXOPool))) - set(UTXOindices))
            
        mixin_tx = []
        while (len(mixin_tx) != mixin_count):
            mixin_tx = mixin_tx + [getRandom() % (len(self.MixinTxPool) + len(rem_utxo_indices))]
            mixin_tx = list(set(mixin_tx))

        for i in range(0, mixin_count):
            index = mixin_tx[i]

            if (index < len(self.MixinTxPool)):
                mixin_tx[i] = self.MixinTxPool[mixin_tx[i]]
            else:
                index = index - len(self.MixinTxPool)
                mixin_tx[i] = self.MyUTXOPool[rem_utxo_indices[index]]

            #If Mixin TX is not encrypted, need to generate commitment to it: v*H
            if (not mixin_tx[i].isEncrypted()):
                mixin_tx[i].c_value = multiply(H, mixin_tx[i].c_value)

        #Generate output transactions
        total_out_value = 0
        for i in range(0, len(in_values)):
            total_out_value = total_out_value + in_values[i]

        if ((pubViewKeys == None) or (pubSpendKeys == None)):
            pubViewKeys = [self.MyPublicViewKey] * len(output_values)
            pubSpendKeys = [self.MyPublicSpendKey] * len(output_values)

        #None = one output of total value
        if (output_values == None):
            output_values = [total_out_value]
        #Int = output count stored instead
        elif (type(output_values) != list):
            v = total_out_value // output_values
            rem = total_out_value - (v*output_values)
            output_values = [v]*output_values
            output_values[-1] = output_values[-1] + rem
        #List = output values specified, create that number of outputs or add extra to account for unspent remainder
        else:
            sum_output_values = 0
            for i in range(0, len(output_values)):
                sum_output_values = sum_output_values + output_values[i]

            #Check to see if enough tokens are avalable in the specified UTXO set
            assert(sum_output_values <= total_out_value)

            #If sum is less than avaiable tokens but not exactly equal, add remaining output value
            if (sum_output_values != total_out_value):
                output_values = output_values + [total_out_value - sum_output_values]

        #Generate Pedersen Commitments
        out_tx = []
        out_rp = []
        out_bf = []
        for i in range(0, len(output_values)):
            (out_rp_val, out_rp_pow10, out_rp_rem, out_rp_bits) = PCRangeProof.GenerateParameters(output_values[i], 4)
            out_bf = out_bf + [getRandom()]
            out_rp = out_rp + [PCRangeProof.Generate(out_rp_val, out_rp_pow10, out_rp_rem, 3, out_bf[i])]
            out_tx = out_tx + [StealthTransaction.Generate_GenRandom(pubViewKeys[i], pubSpendKeys[i], output_values[i], out_bf[i])]        
        
        sig = RingCT.Sign(in_xk, in_values, in_bfs, mixin_tx, out_tx, output_values, out_bf)
        self.MyPendingUTXOPool = self.MyPendingUTXOPool + out_tx

        #Print Information about Transaction
        print("total output value: " + str(total_out_value))

        #Print PC Range Proof Data
        print("===================================================================")
        print("Borromean Range Proof Data")
        print("===================================================================")

        for i in range(0, len(output_values)):
            print("--------------------------------------------")
            print("Range Proof " + str(i+1) + " of " + str(len(output_values)))
            print("Hidden Value = " + str(output_values[i]) + " wei or " + str(output_values[i] / 10**18) + " ETH")
            print("--------------------------------------------")
            out_rp[i].Print_MEW()
        
        #Print Send Data
        print("===================================================================")
        print("Send Tx Data")
        print("===================================================================")
        sig.Print_MEW()
        return (out_rp, sig)

    def GenerateWithdrawTx(self, redeem_eth_address, redeem_eth_value, UTXOindices, mixins=2, output_values=None, pubViewKeys=None, pubSpendKeys=None):
        UTXOindices = list(set(UTXOindices)) #remove duplicates
        mixin_count = len(UTXOindices)*mixins
        if ((len(self.MixinTxPool)+len(self.MyUTXOPool)-len(UTXOindices)) < mixin_count):
            print("Generate Tx failed! Not enough mixins! (req: " + str(mixin_count) + ", have: " + str(len(self.MixinTxPool)+len(self.MyUTXOPool)-len(UTXOindices)) + ")")
            assert(False)
        assert((redeem_eth_value > 0) and (redeem_eth_value < (Ncurve // 2)))

        print("Generating Withdraw Tx...")

        #Get Private Keys, values, and blinding factors from UTXO set
        in_utxos = []
        in_values = [0] * len(UTXOindices)
        in_bfs = [0] * len(UTXOindices)
        in_xk = [0] * len(UTXOindices)
        for i in range(0, len(UTXOindices)):
            in_utxos = in_utxos + [self.MyUTXOPool[UTXOindices[i]]]

            if (in_utxos[i].isEncrypted()):
                (in_values[i], in_bfs[i]) = in_utxos[i].DecryptData(self.MyPrivateSpendKey)
            else:
                (in_values[i], in_bfs[i]) = (in_utxos[i].c_value, 0)
                                             
            in_xk[i] = in_utxos[i].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)

        #Pick random mixin transactions from spent utxos, unknown utxos, and unspent utxos
        rem_utxo_indices = list(set(range(0, len(self.MyUTXOPool))) - set(UTXOindices))
            
        mixin_tx = []
        while (len(mixin_tx) != mixin_count):
            mixin_tx = mixin_tx + [getRandom() % (len(self.MixinTxPool) + len(rem_utxo_indices))]
            mixin_tx = list(set(mixin_tx))

        for i in range(0, mixin_count):
            index = mixin_tx[i]

            if (index < len(self.MixinTxPool)):
                mixin_tx[i] = self.MixinTxPool[mixin_tx[i]]
            else:
                index = index - len(self.MixinTxPool)
                mixin_tx[i] = self.MyUTXOPool[rem_utxo_indices[index]]

            #If Mixin TX is not encrypted, need to generate commitment to it: v*H
            if (not mixin_tx[i].isEncrypted()):
                mixin_tx[i].c_value = multiply(H, mixin_tx[i].c_value)

        #Generate output transactions
        total_out_value = 0
        for i in range(0, len(in_values)):
            total_out_value = total_out_value + in_values[i]

        assert(total_out_value >= redeem_eth_value)
        total_out_value = total_out_value - redeem_eth_value

        if ((pubViewKeys == None) or (pubSpendKeys == None)):
            pubViewKeys = [self.MyPublicViewKey] * len(output_values)
            pubSpendKeys = [self.MyPublicSpendKey] * len(output_values)

        #None = one output of total value
        if (output_values == None):
            output_values = [total_out_value]
        #Int = output count stored instead
        elif (type(output_values) != list):
            v = total_out_value // output_values
            rem = total_out_value - (v*output_values)
            output_values = [v]*output_values
            output_values[-1] = output_values[-1] + rem
        #List = output values specified, create that number of outputs or add extra to account for unspent remainder
        else:
            sum_output_values = 0
            for i in range(0, len(output_values)):
                sum_output_values = sum_output_values + output_values[i]

            #Check to see if enough tokens are avalable in the specified UTXO set
            assert(sum_output_values <= total_out_value)

            #If sum is less than avaiable tokens but not exactly equal, add remaining output value
            if (sum_output_values != total_out_value):
                output_values = output_values + [total_out_value - sum_output_values]

        #Generate Pedersen Commitments
        out_tx = []
        out_rp = []
        out_bf = []
        for i in range(0, len(output_values)):
            (out_rp_val, out_rp_pow10, out_rp_rem, out_rp_bits) = PCRangeProof.GenerateParameters(output_values[i], 4)
            out_bf = out_bf + [getRandom()]
            out_rp = out_rp + [PCRangeProof.Generate(out_rp_val, out_rp_pow10, out_rp_rem, 3, out_bf[i])]
            out_tx = out_tx + [StealthTransaction.Generate_GenRandom(pubViewKeys[i], pubSpendKeys[i], output_values[i], out_bf[i])]
            
        sig = RingCT.Sign(in_xk, in_values, in_bfs, mixin_tx, out_tx, output_values, out_bf, redeem_eth_address, redeem_eth_value)
        self.MyPendingUTXOPool = self.MyPendingUTXOPool + out_tx

        #Print Information about Transaction
        print("total output value: " + str(total_out_value+redeem_eth_value))

        #Print PC Range Proof Data
        print("===================================================================")
        print("Borromean Range Proof Data")
        print("===================================================================")

        for i in range(0, len(output_values)):
            print("--------------------------------------------")
            print("Range Proof " + str(i+1) + " of " + str(len(output_values)))
            print("Hidden Value = " + str(output_values[i]) + " wei or " + str(output_values[i] / 10**18) + " ETH")
            print("--------------------------------------------")
            out_rp[i].Print_MEW()
        
        #Print Send Data
        print("===================================================================")
        print("Send Tx Data")
        print("===================================================================")
        sig.Print_MEW()
        return (out_rp, sig)

    ########################
    # High level functions #
    ########################
    def GetBalance(self):
        token_balance = 0
        for i in range(len(self.MyUTXOPool)):
            token_balance += self.MyUTXOPool[i].DecryptData(self.MyPrivateSpendKey)[0]

        return token_balance

    def Deposit(self, values):
        if (type(values) != list):
            values = [values]

        total_value = 0
        for i in range(0, len(values)):
            total_value += values[i]

        #Generate Deposit UTXOs
        utxo_start_index = len(self.MyPendingUTXOPool)
        self.GeneratePendingUTXOs(values, [0]*len(values))
        
        #Print Deposit Data
        print("===================================================================")
        print("Deposit Data")
        print("===================================================================")
        print("--------------------------------------------")
        print("Total Value: " + str(total_value / 10**18) + " ETH (" + str(total_value) + " wei)")
        print("--------------------------------------------")
        print()
        print("dest_pub_keys:")
        for i in range(utxo_start_index, len(self.MyPendingUTXOPool)):
            if (i > 0):
                print(",")

            print(bytes_to_str(CompressPoint(self.MyPendingUTXOPool[i].pub_key)), end = "")

        print("\n\ndhe_points:")
        for i in range(utxo_start_index, len(self.MyPendingUTXOPool)):
            if (i > 0):
                print(",")
            
            print(bytes_to_str(CompressPoint(self.MyPendingUTXOPool[i].dhe_point)), end = "")

        print("\n\nvalues:")
        for i in range(utxo_start_index, len(self.MyPendingUTXOPool)):
            if (i > 0):
                print(",")
            
            print(str(self.MyPendingUTXOPool[i].DecryptData(self.MyPrivateSpendKey)[0]), end = "")
            

    def Send(self, dest_pub_view_key, dest_pub_spend_key, value, mixin_count=3):
        balance = self.GetBalance()
        if (value > balance):
            print("Failed to generate SendTx, insufficient balance (req: " + str(value / 10**18) + " ETH, have: " + str(balance / 10**18) + ")")

        #Figure out which UTXOs must be spent, pick sequentially for now but may need a better algorithm to preserve privacy
        utxo_indices = []
        utxo_total = 0
        utxo_remainder = 0
        i = 0
        while (utxo_total < value):
            #Fetch UTXO Value
            utxo_value = self.MyUTXOPool[i].DecryptData(self.MyPrivateSpendKey)[0]

            if (utxo_value > 0):
                #Add index
                utxo_indices += [i]
                
                #Add value to utxo total
                utxo_total += utxo_value

                #Is there a remainder?
                if (utxo_total > value):
                    utxo_remainder = (utxo_total - value)
                    utxo_total = value
            
            i += 1

        #Generate Send Transaction
        tx = self.GenerateSendTx(utxo_indices, mixin_count, [utxo_total, utxo_remainder], [dest_pub_view_key, self.MyPublicViewKey], [dest_pub_spend_key, self.MyPublicSpendKey])
        return tx

    def Withdraw(self, redeem_eth_address, value, mixin_count=3):
        balance = self.GetBalance()
        if (value > balance):
            print("Failed to generate WithdrawTx, insufficient balance (req: " + str(value / 10**18) + " ETH, have: " + str(balance / 10**18) + ")")
            
        utxo_indices = []
        utxo_total = 0
        utxo_remainder = 0
        i = 0
        while (utxo_total < value):
            #Fetch UTXO Value
            utxo_value = self.MyUTXOPool[i].DecryptData(self.MyPrivateSpendKey)[0]

            if (utxo_value > 0):
                #Add index
                utxo_indices += [i]
                
                #Add value to utxo total
                utxo_total += utxo_value

                #Is there a remainder?
                if (utxo_total > value):
                    utxo_remainder = (utxo_total - value)
                    utxo_total = value
            
            i += 1

        #Generate Send Transaction
        tx = self.GenerateWithdrawTx(redeem_eth_address, value, utxo_indices, mixin_count, [utxo_remainder], [self.MyPublicViewKey], [self.MyPublicSpendKey])
        return tx        

    #Print Functions
    def PrintStealthAddress(self):
        print("Public View Key:  " + print_point(CompressPoint(self.MyPublicViewKey)))
        print("Public Spend Key: " + print_point(CompressPoint(self.MyPublicSpendKey)))

    def PrintUTXOPool(self):
        for i in range(0, len(self.MyUTXOPool)):
            print("UTXO " + str(i) + ":")
            print("pub key: " + hex(CompressPoint(self.MyUTXOPool[i].pub_key)))
            print("[priv key: " + hex(self.MyUTXOPool[i].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)) + "]")

            if (self.MyUTXOPool[i].isEncrypted()):
                (v, bf) = self.MyUTXOPool[i].DecryptData(self.MyPrivateSpendKey)
                print("[value: " + str(v) + "]")
                print("[bf: " + hex(bf) + "]")
            else:
                print("value: " + str(self.MyUTXOPool[i].c_value))

            print()

    def PrintPendingUTXOPool(self):
        for i in range(0, len(self.MyPendingUTXOPool)):
            print("Pending UTXO " + str(i) + ":")
            print("pub key: " + hex(CompressPoint(self.MyPendingUTXOPool[i].pub_key)))
            print("[priv key: " + hex(self.MyPendingUTXOPool[i].GetPrivKey(self.MyPrivateViewKey, self.MyPrivateSpendKey)) + "]")

            if (self.MyPendingUTXOPool[i].isEncrypted()):
                (v, bf) = self.MyPendingUTXOPool[i].DecryptData(self.MyPrivateSpendKey)
            else:
                v = self.MyPendingUTXOPool[i].c_value
                bf = 0
                
            print("[value: " + str(v) + "]")
            print("[bf: " + hex(bf) + "]")
            print()

    def PrintMixinPool(self):
        print("Mixin Tx Pool:")
        for i in range(0, len(self.MixinTxPool)):
            print("pub key " + str(i) + ": " + hex(CompressPoint(self.MixinTxPool[i].pub_key)))
        print()

    def ExportStealthAddress(self):
        return [self.MyPrivateViewKey, self.MyPrivateSpendKey]

    def ExportStealthAddressToPython(self):
        print("StealthAddressExport = [" + hex(self.MyPrivateViewKey) + ", " + hex(self.MyPrivateSpendKey) + "]")

    def ExportUTXOPool(self):
        pool = []
        for i in range(0, len(self.MyUTXOPool)):
            pool = pool + [[CompressPoint(self.MyUTXOPool[i].pub_key), CompressPoint(self.MyUTXOPool[i].dhe_point),
                           CompressPoint(self.MyUTXOPool[i].c_value), bytes_to_int(self.MyUTXOPool[i].pc_encrypted_data.message),
                           bytes_to_int(self.MyUTXOPool[i].pc_encrypted_data.iv)]]

        return pool

    def ExportUTXOPoolToPython(self):
        print("UTXOPoolExport =\n[", end="")
        for i in range(0, len(self.MyUTXOPool)):
            #[pub_key, dhe_point, c_value, encrypted message, iv]
            print("[" + hex(CompressPoint(self.MyUTXOPool[i].pub_key)) + ",")
            print(" " + hex(CompressPoint(self.MyUTXOPool[i].dhe_point)) + ",")
            print(" " + hex(CompressPoint(self.MyUTXOPool[i].c_value)) + ",")
            print(" " + hex(bytes_to_int(self.MyUTXOPool[i].pc_encrypted_data.message)) + ",")
            print(" " + hex(bytes_to_int(self.MyUTXOPool[i].pc_encrypted_data.iv)) + "]", end= "")

            if (i < (len(self.MyUTXOPool)-1)):
                print(",")
            else:
                print("]")
        print()

    def ExportMixinPool(self):
        pool = []
        for i in range(0, len(self.MixinTxPool)):
            pool = pool + [[CompressPoint(self.MixinTxPool[i].pub_key), CompressPoint(self.MixinTxPool[i].dhe_point),
                           CompressPoint(self.MixinTxPool[i].c_value), bytes_to_int(self.MixinTxPool[i].pc_encrypted_data.message),
                           bytes_to_int(self.MixinTxPool[i].pc_encrypted_data.iv)]]

        return pool

    def ExportMixinPoolToPython(self):
        print("MixinPoolExport =\n[", end="")
        for i in range(0, len(self.MixinTxPool)):
            #[pub_key, dhe_point, c_value, encrypted message, iv]
            print("[" + hex(CompressPoint(self.MixinTxPool[i].pub_key)) + ",")
            print(" " + hex(CompressPoint(self.MixinTxPool[i].dhe_point)) + ",")
            print(" " + hex(CompressPoint(self.MixinTxPool[i].c_value)) + ",")
            print(" " + hex(bytes_to_int(self.MixinTxPool[i].pc_encrypted_data.message)) + ",")
            print(" " + hex(bytes_to_int(self.MixinTxPool[i].pc_encrypted_data.iv)) + "]", end= "")

            if (i < (len(self.MixinTxPool)-1)):
                print(",")
            else:
                print("]")
        print()
