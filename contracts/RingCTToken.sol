pragma solidity ^0.4.24;

import "./Debuggable.sol";
import "./ECMathInterface.sol";
import "./RingCTTxVerifyInterface.sol";
import "./BulletproofVerifyInterface.sol";

/*
Deploy addresses:
"0x4552c90DB760D5380921e18377A41eDCff8D100e",
"0xB2980dDcac235Bfe66135bC9b990eC1b5ED5cCF5",
"0xe126E4614aBC9d0DDc7162d857E33C032bda2271"
*/

contract RingCTToken is RingCTTxVerifyInterface, ECMathInterface, BulletproofVerifyInterface {
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ecMathAddr, address bpVerifyAddr, address ringCTVerifyAddr)
		ECMathInterface(ecMathAddr) BulletproofVerifyInterface(bpVerifyAddr) RingCTTxVerifyInterface(ringCTVerifyAddr) public
	{
		//Nothing left to do
	}
	
	//Events
	event WithdrawalEvent(address indexed _to, uint256 _value);
	event DepositEvent (uint256 indexed _pub_key, uint256 indexed _dhe_point, uint256 _value);
	event SendEvent (uint256 indexed _pub_key, uint256 indexed _value, uint256 indexed _dhe_point, uint256[3] _encrypted_data);
	event PCRangeProvenEvent (uint256 indexed _commitment, uint256 _min, uint256 _max, uint256 _resolution);
	event StealthAddressPublishedEvent(address indexed addr, uint256 indexed pubviewkey, uint256 indexed pubspendkey);
	event StealthAddressPrivateViewKeyPublishedEvent(address indexed addr, uint256 indexed priviewkey);

	//Mapping of EC Public Key to Pedersen Commitment of Value
	mapping (uint256 => uint256) public token_committed_balance;
    
	//Storage array of commitments which have been proven to be positive
	mapping (uint256 => bool) public balance_positive;
	
	//Storage array for key images which have been used
	mapping (uint256 => bool) public key_images;
	
	//Stealth Address Function(s)
    //For a given msg.sender (ETH address) publish EC points for public spend and view keys
    //These EC points will be used to generate stealth addresses
    function PublishStealthAddress(uint256 stx_pubviewkey, uint256 stx_pubspendkey) public
    {
		emit StealthAddressPublishedEvent(msg.sender, stx_pubviewkey, stx_pubspendkey);
    }
	
	//Optionally publish view key so that private values may be exposed (see Monero for reasons why this would be desirable)
	function PublishPrivateViewKey(uint256 stx_priviewkey) public
	{
		emit StealthAddressPrivateViewKeyPublishedEvent(msg.sender, stx_priviewkey);
	}
    
    //Transaction Functions	
	//Deposit Ether as CT tokens to the specified alt_bn_128 public keys
	//NOTE: this deposited amount will NOT be confidential, initial blinding factor = 0
	function Deposit(uint256[] dest_pub_keys, uint256[] dhe_points, uint256[] values)
	    payable requireECMath public
    {
        //Incoming Value must be non-zero
        require(msg.value > 0);
        
        //One value per public key
        require(dest_pub_keys.length == values.length);
    	
    	//Destination Public Keys must be unused, and
    	//Values must add up to msg.value and each must not excede msg.value (prevent overflow)
    	uint256 i;
    	uint256 v;
    	for (i = 0; i < dest_pub_keys.length; i++) {
    	    require(token_committed_balance[dest_pub_keys[i]] == 0);
    	    
    	    require(values[i] <= msg.value);
    	    v = v + values[i];
    	}
    	
    	require(v == msg.value);

        //Create Tokens
    	for (i = 0; i < dest_pub_keys.length; i++) {
        	//Generate pedersen commitment and add to existing balance
        	token_committed_balance[dest_pub_keys[i]] = ecMath.CompressPoint(ecMath.MultiplyH(values[i]));
    	
    	    //Log new stealth transaction
			emit DepositEvent(dest_pub_keys[i], dhe_points[i], values[i]);
    	}
    }
	
	//Verify Pedersen Commitment is positive using a Borromean Range Proof
    //Arguments are serialized to minimize stack depth.  See libBorromeanRangeProofStruct.sol
    function VerifyPCBorromeanRangeProof(uint256[] rpSerialized, uint64 power10, uint64 offset)
        public requireRingCTTxVerify returns (bool success)
    {
		//Limit power10 and offset
		if (power10 > 35) return false;
		if (offset > (ecMath.GetNCurve() / 4)) return false;
		
		//Verify Borromean Range Proof
		success = ringcttxverify.VerifyBorromeanRangeProof(rpSerialized);
		
		if (success) {
		    //Deserialize arguments
		    BorromeanRangeProofStruct.Data memory args = BorromeanRangeProofStruct.Deserialize(rpSerialized);
		    
			//Calculate (10^power10)*V = (10^power10)*(v*H + bf*G1) = v*(10^power10)*H + bf*(10^power10)*G1
			if (power10 != 0) {
				args.total_commit = ecMath.Multiply(args.total_commit, 10**uint256(power10));
			}
		
			//Calculate V + offset*H = v*H + bf*G1 + offset*H = (v + offset)*H + bf*G1
			if (offset != 0) {
				args.total_commit = ecMath.AddMultiplyH(args.total_commit, offset);
			}
			
			balance_positive[ecMath.CompressPoint(args.total_commit)] = true;
			
			uint256[3] memory temp;
			temp[0] = (args.bit_commits.length / 2);    //Bits
			temp[1] = (10**uint256(power10));           //Resolution
			temp[2] = (4**temp[0]-1)*temp[1]+offset;    //Max Value
			emit PCRangeProvenEvent(ecMath.CompressPoint(args.total_commit), offset, temp[2], temp[1]);
		}
	}
	
	//Verify Pedersen Commitment is positive using Bullet Proof(s)
	//Arguments are serialized to minimize stack depth.  See libBulletproofStruct.sol
	function VerifyPCBulletProof(uint256[] bpSerialized, uint64[] power10, uint64[] offsets)
		public requireECMath requireBulletproofVerify returns (bool success)
	{
	    //Deserialize Bullet Proof
	    BulletproofStruct.Data[] memory args = BulletproofStruct.Deserialize(bpSerialized);
	    
	    //Check inputs for each proof
	    uint256 p;
	    uint256 i;
		uint256 offset_index = 0;
		
	    for (p = 0; p < args.length; p++) {
    		//Check inputs
    		if (args[p].V.length < 2) return false;
    		if (args[p].V.length % 2 != 0) return false;
			if (args[p].N > 64) return false;
    		
    		//Count number of committments
    		offset_index += (args[p].V.length / 2);
	    }
	    
	    //Check offsets and power10 length
	    if (offsets.length != offset_index) return false;
    	if (power10.length != offset_index) return false;
		
		//Limit power10, offsets, and N so that commitments do not overflow (even if "positive")		
		for (i = 0; i < offsets.length; i++) {
			if (offsets[i] > (ecMath.GetNCurve() / 4)) return false;
			if (power10[i] > 35) return false;
		}
		
		//Verify Bulletproof(s)
		success = bpVerify.VerifyBulletproof(bpSerialized);

		uint256[2] memory point;
		uint256[2] memory temp;
		if (success) {
			//Add known powers of 10 and offsets to committments and mark as positive
			//Note that multiplying the commitment by a power of 10 also affects the blinding factor as well
			offset_index = 0;
			
			for (p = 0; p < args.length; p++) {
				for (i = 0; i < args[p].V.length; i += 2) {
				    //Pull commitment
				    point = [args[p].V[i], args[p].V[i+1]];
				    
    				//Calculate (10^power10)*V = (10^power10)*(v*H + bf*G1) = v*(10^power10)*H + bf*(10^power10)*G1
    				if (power10[offset_index] != 0) {
    					point = ecMath.Multiply(point, 10**uint256(power10[offset_index]));
    				}
    			
    				//Calculate V + offset*H = v*H + bf*G1 + offset*H = (v + offset)*H + bf*G1
    				if (offsets[offset_index] != 0) {
    					point = ecMath.AddMultiplyH(point, offsets[offset_index]);
    				}
    				
    				//Mark balance as positive
    				point[0] = ecMath.CompressPoint(point);
    				balance_positive[point[0]] = true;
    				
    				//Emit event
    				temp[0] = (10**uint256(power10[offset_index]));                     //Resolution
    				temp[1] = (2**args[p].N-1)*temp[0]+offsets[offset_index];  //Max Value
    				emit PCRangeProvenEvent(point[0], offsets[offset_index], temp[1], temp[0]);
					
					//Increment indices
					offset_index++;
				}
			}
		}
	}
    
	//Process Tranasaction using RingCT
	//This function handles both token transfers and token redemptions for ETH
	//Arguments are serialized to minimize stack depth.  See libRingCTTxStruct.sol
    function Send(uint256[] argsSerialized)
        public requireECMath requireRingCTTxVerify returns (bool success)
    {
		//Deserialize arguments into RingCTTxStruct
        RingCTTxStruct.Data memory args = RingCTTxStruct.Deserialize(argsSerialized);
		
		//Get committed token balances and insert them into each input UTXO	    
        uint256 i;
        uint256 temp;
		
		for (i = 0; i < args.input_tx.length; i++) {
			//Compress Public Key and fetch committed value
			temp = token_committed_balance[ecMath.CompressPoint(args.input_tx[i].pub_key)];
			
		    //Check that committed value is non-zero
			if (temp == 0) return false;
			
			//Store committed value
			args.input_tx[i].value = ecMath.ExpandPoint(temp);
		}
		
		//Verify output commitments have been proven positive
        for (i = 0; i < args.output_tx.length; i++) {
            if (!balance_positive[ecMath.CompressPoint(args.output_tx[i].value)]) return false;
        }
		
		//Verify key images are unused
        uint256 index = 0;
        for (i = 0; i < (args.I.length / 2); i++) {
            if (key_images[ecMath.CompressPoint([args.I[index], args.I[index+1]])]) return false;
			index += 2;
        }
		
		//Check Ring CT Tx for Validity
		//args must be reserialized as the committed values have been added by this contract
        if (!ringcttxverify.ValidateRingCTTx(RingCTTxStruct.Serialize(args))) return false;
		
		//RingCT Tx has been verified.  Now execute it.
		//Spend UTXOs and generate new UTXOs
		uint256 pub_key;
        uint256 value;
		
		//Save key images to prevent double spends
		index = 0;
        for (i = 0; i < (args.I.length / 2); i++) {
            key_images[ecMath.CompressPoint([args.I[index], args.I[index+1]])] = true;
            index += 2;
        }
		
		//Generate new UTXO's
		for (i = 0; i < (args.output_tx.length); i++) {
			pub_key = ecMath.CompressPoint(args.output_tx[i].pub_key);
			value = ecMath.CompressPoint(args.output_tx[i].value);
			
			//Store output commitment and public key
			token_committed_balance[pub_key] = value;		
			
			//Unmark balance positive to free up space
			//Realistically there is no situation in which using the same output commitment will be useful
			balance_positive[value] = false;

			//Log new stealth transaction
			emit SendEvent(pub_key, value, ecMath.CompressPoint(args.output_tx[i].dhe_point), args.output_tx[i].encrypted_data);
		}
		
		//Process Withdrawal if part of transaction
		if (args.redeem_eth_value > 0) {
			//Send redeemed value to ETH address
			//If ETH address is 0x0, redeem the ETH to sender of the transaction
			//This can be used to pay others to broadcast transactions for you
			if (args.redeem_eth_address == 0) {
				args.redeem_eth_address = msg.sender;
			}
			
			args.redeem_eth_address.transfer(args.redeem_eth_value);
			
			//Log Withdrawal
			emit WithdrawalEvent(args.redeem_eth_address, args.redeem_eth_value);
		}
		
		return true;
    }
}