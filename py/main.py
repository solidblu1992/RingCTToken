#Imports
import json
from web3 import Web3, HTTPProvider
from web3.contract import Contract

from web3 import Web3, HTTPProvider, TestRPCProvider
from web3.middleware import geth_poa_middleware
import csv
from RingCTToken import *

##############
# Fetch Web3 #
##############
print("Starting Web3")
web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
web3.middleware_stack.inject(geth_poa_middleware, layer=0)

#############################
# Get RingCT Token Contract #
#############################
print("Initializing RingCT Token Contract")
contract_addr = "0x8F108AEf7bAA1E42084653896bE6E16eC6623dDe";
contract_abi = open("RingCTToken.json").read()
contract = web3.eth.contract(address=contract_addr,
                             abi=contract_abi,
                             ContractFactoryClass=Contract)

#Set Ether Address and Stealth Address
EthAddress = 0x975C076706FcfaCc721EC31b2f9fC2e41B8c596f
StealthAddress1 = [0x95169576339c26b437843b4a8a14bccbde711e7223691c8f435069d4c6bd2d8, 0xe1442d1972fb38a3f87a8432a13e086b94386336c41fb999a5f2028dae9dffa]
rct = RingCTToken()
rct.SetStealthAddress(StealthAddress1[0], StealthAddress1[1])

##############################
# Import UTXO Pool from File #
##############################
try:
    fromBlock = 0
    UTXOImport = []
    with open("utxo.csv", "r") as file:
        print("UTXO file found, importing")
        reader = csv.reader(file, delimiter=",")
        for row in reader:
            if (row[0] == "block_number"):
                fromBlock = int(row[1])

            try:
                #Test row for integer data
                x = int(row[0], 16)
                
            except ValueError:
                pass

            else:
                pub_key = ExpandPoint(int(row[0],16))
                dhe_point = ExpandPoint(int(row[1],16))

                try:
                    c_value = int(row[2],10)
                    tx = StealthTransaction(pub_key, dhe_point, c_value)
                except ValueError:
                    c_value = ExpandPoint(int(row[2],16))
                    encrypted_data = PCAESMessage(int_to_bytes64(int(row[3],16)), int_to_bytes16(int(row[4],16)))
                    tx = StealthTransaction(pub_key, dhe_point, c_value, encrypted_data)

                (owned, duplicate) = rct.AddTx(tx)
                if (owned and not duplicate):
                    priv_key = tx.GetPrivKey(rct.MyPrivateViewKey, rct.MyPrivateSpendKey)
                    spent = contract.functions.key_images(CompressPoint(KeyImage(priv_key))).call()

                    if (spent):
                        rct.MarkUTXOAsSpent(len(rct.MyUTXOPool)-1)
                    
except FileNotFoundError:
    print("UTXO file not found, starting import at block 0")

#######################
# Setup Event Filters #
#######################
toBlock = web3.eth.blockNumber
print("Retreiving events starting at block=" + str(fromBlock))
PCRangeProvenEF = contract.events.PCRangeProvenEvent.createFilter(fromBlock=fromBlock)
SendEF = contract.events.SendEvent.createFilter(fromBlock=fromBlock)
StealthAddressPublishedEF = contract.events.StealthAddressPublishedEvent.createFilter(fromBlock=fromBlock)
DepositEF = contract.events.DepositEvent.createFilter(fromBlock=fromBlock)
WithdrawalEF = contract.events.WithdrawalEvent.createFilter(fromBlock=fromBlock)

#Processs positive commitments
if (False):
    print()
    entries = PCRangeProvenEF.get_all_entries()
    for i in range(0, len(entries)):
        print("Commitment[" + str(i) + "]: ", end="")
        print(bytes32_to_str(entries[i].args.get('_commitment')) + " proven positive, (", end="")
        print(str(entries[i].args.get('_min') / 10**18) + ", ", end="")
        print(str(entries[i].args.get('_resolution') / 10**18) + ", ..., ", end="")
        print(str(entries[i].args.get('_max') / 10**18) + " ETH)")

#Process Withdrawal Events
if (True):
    print()
    entries = WithdrawalEF.get_all_entries()
    for i in range(0, len(entries)):
        addr = int(entries[i].args.get('_to'), 16)
        value = entries[i].args.get('_value')

        if(addr == EthAddress):
            print("Withdrawal[" + str(i) + "]: " + bytes_to_str(addr, 20) + " received " + str(value / 10**18) + " ETH (" + str(value) + " wei)")

#Process Deposit Events
entries = DepositEF.get_all_entries()
for i in range(0, len(entries)):
    pub_key = entries[i].args.get('_pub_key')
    dhe_point = entries[i].args.get('_dhe_point')
    value = entries[i].args.get('_value')

    tx = StealthTransaction(ExpandPoint(pub_key), ExpandPoint(dhe_point), value)
    (owned, duplicate) = rct.AddTx(tx)

    if (not duplicate):
        if (owned):
            priv_key = tx.GetPrivKey(rct.MyPrivateViewKey, rct.MyPrivateSpendKey)
            spent = contract.functions.key_images(CompressPoint(KeyImage(priv_key))).call()

            if (spent):
                rct.MarkUTXOAsSpent(len(rct.MyUTXOPool)-1)
        
        if (True and not spent):
            print()
            print("DepositEvent[" + str(i) + "]:")
            print("dest_pub_key: " + bytes_to_str(pub_key))
            print("dhe_point:    " + bytes_to_str(dhe_point))
            print("value:        " + str(value / 10**18) + " ETH (" + str(value) + " wei)")
            print("owned:        " + str(owned))

            if (owned):
                print("[priv_key:    " + bytes_to_str(priv_key) + "]")
                print("[spent:       " + str(spent) + "]")
                
            print()
        

#Process Send Events
entries = SendEF.get_all_entries()
for i in range(0, len(entries)):
    pub_key = entries[i].args.get('_pub_key')
    dhe_point = entries[i].args.get('_dhe_point')
    value = entries[i].args.get('_value')
    encrypted_data_raw = entries[i].args.get('_encrypted_data')
    encrypted_data = PCAESMessage(int_to_bytes32(encrypted_data_raw[0]) + int_to_bytes32(encrypted_data_raw[1]), int_to_bytes16(encrypted_data_raw[2]))

    tx = StealthTransaction(ExpandPoint(pub_key), ExpandPoint(dhe_point), ExpandPoint(value), encrypted_data)
    (owned, duplicate) = rct.AddTx(tx)

    if (not duplicate):
        if (owned):
            priv_key = tx.GetPrivKey(rct.MyPrivateViewKey, rct.MyPrivateSpendKey)
            (value, bf) = tx.DecryptData(rct.MyPrivateSpendKey)
            print()
            spent = contract.functions.key_images(CompressPoint(KeyImage(priv_key))).call()

            if (spent):
                rct.MarkUTXOAsSpent(len(rct.MyUTXOPool)-1)
                
        if (True and not spent):
            print()
            print("SendEvent[" + str(i) + "]:")
            print("dest_pub_key:   " + bytes_to_str(pub_key))
            print("dhe_point:      " + bytes_to_str(dhe_point))
            print("c_value:        " + bytes_to_str(value))
            print("encrypted_msg:  " + bytes_to_str(bytes_to_int(encrypted_data.message), 64))
            print("encrypted_iv:   " + bytes_to_str(bytes_to_int(encrypted_data.iv), 16))

            if (owned):
                print("[priv_key:      " + bytes_to_str(priv_key) + "]")
                print("[bf:            " + bytes_to_str(bf) + "]")
                print("[value:         " + str(value / 10**18) + " ETH (" + str(value) + " wei)]")
                print("[spent:         " + str(spent) + "]")
            print()

###########################################
# Export UTXO Pool and Mixin Pool to file #
###########################################
print("Import complete, writing to csv file")
with open("utxo.csv", "w") as file:
    writer = csv.writer(file, delimiter=",")
    writer.writerow(["block_number", str(toBlock)])
    writer.writerow(["utxo_set"])
    writer.writerow(["pub_key", "dhe_point", "c_value", "encrypted_data.msg", "encrypted_data.iv"])

    for i in range(0, len(rct.MyUTXOPool)):
        row_data = [bytes_to_str(CompressPoint(rct.MyUTXOPool[i].pub_key)),
                    bytes_to_str(CompressPoint(rct.MyUTXOPool[i].dhe_point))]

        if (type(rct.MyUTXOPool[i].c_value) == tuple):
            row_data += [bytes_to_str(CompressPoint(rct.MyUTXOPool[i].c_value))]
        else:
            row_data += [str(rct.MyUTXOPool[i].c_value)]

        if (rct.MyUTXOPool[i].isEncrypted()):
            row_data += [bytes_to_str(bytes_to_int(rct.MyUTXOPool[i].pc_encrypted_data.message),64),
                         bytes_to_str(bytes_to_int(rct.MyUTXOPool[i].pc_encrypted_data.iv), 16)]
        else:
            row_data += ["0x0", "0x0"]
            
        writer.writerow(row_data)

    writer.writerow(["mixin_set"])
    writer.writerow(["pub_key", "dhe_point", "c_value", "encrypted_data.msg", "encrypted_data.iv"])
        
    for i in range(0, len(rct.MixinTxPool)):
        row_data = [bytes_to_str(CompressPoint(rct.MixinTxPool[i].pub_key)),
                    bytes_to_str(CompressPoint(rct.MixinTxPool[i].dhe_point))]

        if (type(rct.MixinTxPool[i].c_value) == tuple):
            row_data += [bytes_to_str(CompressPoint(rct.MixinTxPool[i].c_value))]
        else:
            row_data += [str(rct.MixinTxPool[i].c_value)]

        if (rct.MixinTxPool[i].isEncrypted()):
            row_data += [bytes_to_str(bytes_to_int(rct.MixinTxPool[i].pc_encrypted_data.message),64),
                         bytes_to_str(bytes_to_int(rct.MixinTxPool[i].pc_encrypted_data.iv), 16)]
        else:
            row_data += ["0x0", "0x0"]
            
        writer.writerow(row_data)

    file.close()

#####################
# Get Token Balance #
#####################
balance = rct.GetBalance()
print("Token Balance: " + str(balance / 10**18) + " ETH (" + str(balance) + " wei)")

#Generate Transactions
#Deposit
if (False):
    deposit_count = 16
    deposit_value = 10**16
    rct.Deposit([deposit_value]*deposit_count)
    
#Spend
if (True):
    StealthAddress2 = [0x4c9533a55063b232b3e5d7381ba19238048e1372f3c75c4cc958d9d3b122e, 0x243a70b7099a51906eeba778a1b1c16f2c3c0e092df326cd4148f8c5c86153ee]
    dest_rct = RingCTToken()
    dest_rct.SetStealthAddress(StealthAddress2[0], StealthAddress2[1])
    
    tx = rct.Send(dest_rct.MyPublicViewKey, dest_rct.MyPublicSpendKey, 10**15, mixin_count=3)

    x = web3.IPCProviderweb3.eth.abi.encodeParameter("uint256[]", tx[1].Serialize())

#Withdraw
if (False):
    tx = rct.Withdraw(EthAddress, 9000000000000000, mixin_count=3)
