pragma solidity ^0.4.13;

contract BulletproofVerify {
    //Verify Bulletproof(s), can do multiple commitements and multiple proofs at once
    //This function's arguments are serialized into uint256[] array so it can be called externally w/o abi encoding
	function VerifyBulletproof(uint256[] argsSerialized) public view returns (bool);
}

contract Debuggable {
    //Debug Code
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier ownerOnly {
        if ( (msg.sender != owner) && (owner != 0) ) revert();
        _;
    }
    
	function Kill() public ownerOnly {
    	selfdestruct(msg.sender);
	}
	
	event DebugEvent(string marker, uint256 data);
	event DebugEvent2(string marker, uint256[] data);
}

contract BulletproofVerifyInterface is Debuggable {
    //Prerequisite Contract(s)
	BulletproofVerify bpVerify;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function BulletproofVerify_GetAddress() public constant returns (address) {
	    return address(bpVerify);
	}
	
	function BulletproofVerify_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = BulletproofVerify_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function BulletproofVerify_ChangeAddress(address bpVerifyAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//assert(BulletproofVerify_GetCodeSize() == 0);
		
		bpVerify = BulletproofVerify(bpVerifyAddr);
		emit ContractAddressChanged("BulletproofVerify", bpVerifyAddr);
	}
	
	modifier requireBulletproofVerify {
	    require(BulletproofVerify_GetCodeSize() > 0);
	    _;
	}
	
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address bpVerifyAddr) public {
	    BulletproofVerify_ChangeAddress(bpVerifyAddr);
	}
}

contract ECMath {
	//Base EC Parameters
	function GetG1() public view returns (uint256[2]);
	function GetH() public view returns (uint256[2]);
	function GetInfinity() public view returns (uint256[2]);
	function GetNCurve() public pure returns (uint256);
	function GetPCurve() public pure returns (uint256);
	function GetGiHi(uint256 N) public constant returns (uint256[], uint256[]);
	function GetGiHiLength() public view returns (uint256);
	
	//Base EC Functions
	function Negate(uint256[2] p1) public pure returns (uint256[2] p2);
	function Equals(uint256[2] p1, uint256[2] p2) public pure returns (bool);
	function Add(uint256[2] p0, uint256[2] p1) public constant returns (uint256[2] p2);
	function Subtract(uint256[2] p0, uint256[2] p1) public constant returns (uint256[2] p2);
	function Multiply(uint256[2] p0, uint256 s) public constant returns (uint256[2] p1);
	
	//Shortcut Functions
	function MultiplyG1(uint256 s) public constant returns (uint256[2] p0);
	function MultiplyH(uint256 s) public constant returns (uint256[2] p0);
    function AddMultiply(uint256[2] p_add, uint256[2] p_mul, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*p_mul
	function AddMultiplyG1(uint256[2] p_add, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*G1
    function AddMultiplyH(uint256[2] p_add, uint256 s) public constant returns (uint256[2] p0); //Returns p0 = p_add + s*H
    function CommitG1H(uint256 s_G1, uint256 s_H) public constant returns (uint256[2] p0); //Returns s_G1*G1 + s_H*H
	
	//Vector Functions
	function VectorScale(uint256[] X, uint256 s) public constant returns (uint256[] Z);
	function VectorAdd(uint256[] X, uint256[] Y) public constant returns (uint256[] Z);
	function VectorMul(uint256[] X, uint256[] s) public constant returns (uint256[] Z);
	
	//Returns s0*P0 + s1*P1 + ... + sk*Pk
    function MultiExp(uint256[] P, uint256[] s, uint256 start, uint256 end) public constant returns (uint256[2] Pout);
	
	//Returns Pin + s0*P0 + s1*P1 + ... + sk*Pk
	function AddMultiExp(uint256[2] Pin, uint256[] P, uint256[] s, uint256 start, uint256 end) public constant returns (uint256[2] Pout);
	
	//Returns px = x[0]*X[0] + x[1]*X[1] + ... + x[n-1]*X[n-1]
    //    and py = y[0]*Y[0] + y[1]*Y[1] + ... + y[n-1]*Y[n-1]
    function CommitAB(uint256[] X, uint256[] Y, uint256[] x, uint256[] y) public constant returns (uint256[2] px, uint256[2] py);
        
	//Point Compression and Expansion Functions
	function CompressPoint(uint256[2] Pin) public pure returns (uint256 Pout);
	function EvaluateCurve(uint256 x) public constant returns (uint256 y, bool onCurve);
	function ExpandPoint(uint256 Pin) public constant returns (uint256[2] Pout);
	
	//Address Functions
	function GetAddress(uint256[2] PubKey) public pure returns (address addr);    
    function GetPublicKeyFromPrivateKey(uint256 privatekey) public constant returns (uint256[2] PubKey);    
    function GetAddressFromPrivateKey(uint256 privatekey) public constant returns (address addr);

    //Return H = keccak256(p)
    function HashOfPoint(uint256[2] point) public pure returns (uint256 h);
    
	//Return H = alt_bn128 evaluated at keccak256(p)
    function HashToPoint(uint256[2] p) public constant returns (uint256[2] h);
}

contract ECMathInterface is Debuggable {
    //Prerequisite Contract(s)
	ECMath ecMath;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function ECMath_GetAddress() public constant returns (address) {
	    return address(ecMath);
	}
	
	function ECMath_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = ECMath_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function ECMath_ChangeAddress(address ecMathAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//assert(ECMath_GetCodeSize() == 0);
		
		ecMath = ECMath(ecMathAddr);
		emit ContractAddressChanged("ECMath", ecMathAddr);
	}
	
	modifier requireECMath {
	    require(ECMath_GetCodeSize() > 0);
	    _;
	}
	
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ecMathAddr) public {
	    ECMath_ChangeAddress(ecMathAddr);
	}
}

contract RingCTTxVerify {    
    //Serialized version of ValidateRingCTTx.  This version does not use structs so that it can be called publicly.
	function ValidateRingCTTx(uint256[] argsSerialized) public view returns (bool);
    
    //Serialized version of VerifyBorromeanRangeProof.  This version does not use structs so that it can be called publicly.
	function VerifyBorromeanRangeProof(uint256[] argsSerialized) public view returns (bool);
	
    //Utility Functions
	function HashSendMsg(uint256[] output_pub_keys, uint256[] output_values, uint256[] output_dhe_points, uint256[] output_encrypted_data)
							public pure returns (uint256 msgHash);		

	function HashWithdrawMsg(address ethAddress, uint256 value,
								uint256[] output_pub_keys, uint256[] output_values, uint256[] output_dhe_points, uint256[] output_encrypted_data)
								public pure returns (uint256 msgHash);
}

contract RingCTTxVerifyInterface is Debuggable {
    //Prerequisite Contract(s)
	RingCTTxVerify ringcttxverify;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function RingCTTxVerify_GetAddress() public constant returns (address) {
		return address(ringcttxverify);
	}
	
	function RingCTTxVerify_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = RingCTTxVerify_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function RingCTTxVerify_ChangeAddress(address ringCTTxVerifyAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//require(RingCTTxVerify_GetCodeSize() == 0);
		
		ringcttxverify = RingCTTxVerify(ringCTTxVerifyAddr);
		emit ContractAddressChanged("RingCTTxVerify", ringCTTxVerifyAddr);
	}
	
	modifier requireRingCTTxVerify {
	    require(RingCTTxVerify_GetCodeSize() > 0);
	    _;
	}

	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ringCTTxVerifyAddr) public {
	    RingCTTxVerify_ChangeAddress(ringCTTxVerifyAddr);
	}
}

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

library BorromeanRangeProofStruct {
	//Structure for VerifyPCRangeProof() arguments
	struct Data {
		uint256[2] total_commit;
		uint256[] bit_commits;
		uint256[] signature;
	}
	
	//Creates Borromean Range Proof Args struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data args)
	{
		//Check input length, need at least 3 arguments - assuming all variable arrays are zero length and only store the size
		require(argsSerialized.length >= 3);
		
		//Deserialize
		uint256 i;
		uint256 index;
		uint256 length;
		args.total_commit = [argsSerialized[0], argsSerialized[1]];
		
		//Initialize Arrays
		length = (argsSerialized[2] & 0xFFFFFFFFFFFFFFFF);
		if (length > 0) args.bit_commits = new uint256[](length);
		
		length = (argsSerialized[2] & (0xFFFFFFFFFFFFFFFF << 64)) >> 64;
		if (length > 0) args.signature = new uint256[](length);
		
		//Check input length again
		require(argsSerialized.length >= (3 + args.bit_commits.length + args.signature.length));
		
		//Assemble the rest of args
		index = 3;
		for (i = 0; i < args.bit_commits.length; i++) {
			args.bit_commits[i] = argsSerialized[index+i];
		}
		index = index + args.bit_commits.length;
		
		for (i = 0; i < args.signature.length; i++) {
			args.signature[i] = argsSerialized[index+i];
		}
	}
	
	//Decomposes Borromean Range Proof Args struct into uint256 array
	function Serialize(Data args)
		internal pure returns (uint256[] argsSerialized)
	{
		argsSerialized = new uint256[](3 + args.bit_commits.length + args.signature.length);
		
		argsSerialized[0] = args.total_commit[0];
		argsSerialized[1] = args.total_commit[1];
		
		argsSerialized[2] = (args.bit_commits.length & 0xFFFFFFFFFFFFFFFF);
		argsSerialized[2] |= (args.signature.length & 0xFFFFFFFFFFFFFFFF) << 64;
		
		uint256 i;
		uint256 index = 3;		
		for (i = 0; i < args.bit_commits.length; i++) {
		    argsSerialized[index+i] = args.bit_commits[i];
		}
		index = index + args.bit_commits.length;
		
		for (i = 0; i < args.signature.length; i++) {
		    argsSerialized[index+i] = args.signature[i];
		}
	}
	
	function EchoTest(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return Serialize(Deserialize(argsSerialized));
	}
}

library BulletproofStruct {
	//Structure for VerifyBulletproof() arguments
	struct Data {
		uint256[] V;
		uint256[2] A;
		uint256[2] S;
		uint256[2] T1;
		uint256[2] T2;
		uint256 taux;
		uint256 mu;
		uint256[] L;
		uint256[] R;
		uint256 a;
		uint256 b;
		uint256 t;
		uint256 N;
	}	

	//Creates Bullet Proof struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data[] args)
	{
		//Check input length, need at least 1 argument - assuming all variable arrays are zero length and only store the size
		require(argsSerialized.length >= 1);
		
		//Deserialize
		uint256 i;
		uint256 proof;
		uint256 index;
		uint256 length;
		
		//Get proof count
		length = argsSerialized[0];
		args = new Data[](length);
		
		index = 1;
		for (proof = 0; proof < args.length; proof++) {
			//Retreive N
			args[proof].N = (argsSerialized[index] & 0xFFFFFFFFFFFFFFFF);
		
		    //Initialize V, L, and R arrays
		    length = (argsSerialized[index] & (0xFFFFFFFFFFFFFFFF << 64)) >> 64;
		    if (length > 0) args[proof].V = new uint256[](length);
		    
            length = (argsSerialized[index] & (0xFFFFFFFFFFFFFFFF << 128)) >> 128;
    		if (length > 0) args[proof].L = new uint256[](length);
    		
    		length = (argsSerialized[index] & (0xFFFFFFFFFFFFFFFF << 192)) >> 192;
    		if (length > 0) args[proof].R = new uint256[](length);
    		
    		//Check array length again
    		require(argsSerialized.length >= (index + 14 +
    		                                    args[proof].V.length +
    		                                    args[proof].L.length +
    		                                    args[proof].R.length));
    		index += 1;
		    
		    //Get V array
		    length = args[proof].V.length;
		    for (i = 0; i < length; i++) {
		        args[proof].V[i] = argsSerialized[index+i];
		    }
		    index += length;
		    
		    //Get A, S, T1, taux, an mu
    		args[proof].A = [argsSerialized[index], argsSerialized[index+1]];
    		args[proof].S = [argsSerialized[index+2], argsSerialized[index+3]];
    		args[proof].T1 = [argsSerialized[index+4], argsSerialized[index+5]];
    		args[proof].T2 = [argsSerialized[index+6], argsSerialized[index+7]];
    		args[proof].taux = argsSerialized[index+8];
    		args[proof].mu = argsSerialized[index+9];
    		index += 10;
    		
    		//Get L Array
    		length = args[proof].L.length;
    		for (i = 0; i < length; i++) {
    			args[proof].L[i] = argsSerialized[index+i];
    		}
    		index += length;
    		
    		length = args[proof].R.length;
    		for (i = 0; i < length; i++) {
    			args[proof].R[i] = argsSerialized[index+i];
    		}
    		index += length;
    		
    		args[proof].a = argsSerialized[index];
    		args[proof].b = argsSerialized[index+1];
    		args[proof].t = argsSerialized[index+2];
    		index += 3;
		}
	}
	
	//Decomposes Bulletproof struct into uint256 array
	function Serialize(Data[] args)
		internal pure returns (uint256[] argsSerialized)
	{
	    //Calculate total args length
	    uint256 proof;
	    uint256 length = 1;
	    for (proof = 0; proof < args.length; proof++) {
	        length += 14 + args[proof].V.length + args[proof].L.length + args[proof].R.length;
	    }
		argsSerialized = new uint256[](length);
		
		//Store proof count
		argsSerialized[0] = args.length;
		
		//Assemble proofs
		uint256 i;
	    uint256 index = 1;
		for (proof = 0; proof < args.length; proof++) {
		    //Store V, L, and R sizes as well as N
			argsSerialized[index] = (args[proof].N & 0xFFFFFFFFFFFFFFFF);
		    argsSerialized[index] |= (args[proof].V.length & 0xFFFFFFFFFFFFFFFF) << 64;
		    argsSerialized[index] |= (args[proof].L.length & 0xFFFFFFFFFFFFFFFF) << 128;
		    argsSerialized[index] |= (args[proof].R.length & 0xFFFFFFFFFFFFFFFF) << 192;
		    index += 1;
		    
		    //Store V[]
		    length = args[proof].V.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].V[i];
		    }
		    index += length;
		    
		    //Store A, S, T1, T2, taux, mu, len(L), and len(R)
		    argsSerialized[index] = args[proof].A[0];
    		argsSerialized[index+1] = args[proof].A[1];
    		argsSerialized[index+2] = args[proof].S[0];
    		argsSerialized[index+3] = args[proof].S[1];
    		argsSerialized[index+4] = args[proof].T1[0];
    		argsSerialized[index+5] = args[proof].T1[1];
    		argsSerialized[index+6] = args[proof].T2[0];
    		argsSerialized[index+7] = args[proof].T2[1];
    		argsSerialized[index+8] = args[proof].taux;
    		argsSerialized[index+9] = args[proof].mu;
    		index += 10;
    		
    		//Store L[]
    		length = args[proof].L.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].L[i];
		    }
		    index += length;

    		//Store R[]
    		length = args[proof].R.length;
		    for (i = 0; i < length; i++) {
		        argsSerialized[index+i] = args[proof].R[i];
		    }
		    index += length;
		    
		    //Store a, b, t, and N
		    argsSerialized[index] = args[proof].a;
		    argsSerialized[index+1] = args[proof].b;
		    argsSerialized[index+2] = args[proof].t;
		    index += 3;
		}
	}
	
	function EchoTest(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return Serialize(Deserialize(argsSerialized));
	}
}

library RingCTTxStruct {
    //Structure for ValidateRingCTTx() arguments
    struct Data {
		address redeem_eth_address;
		uint256 redeem_eth_value;
		UTXO.Input[] input_tx;
		UTXO.Output[] output_tx;
		uint256[] I;
		uint256[] signature;
	}
    
    //Creates RingCT Tx Args struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data args)
	{
		//Check input length, need at least 3 arguments - assuming all arrays are zero length and only store the size
		require(argsSerialized.length >= 3);
		
		//Deserialize
		uint256 i;
		uint256 index;
		uint256 length;
		args.redeem_eth_address = address(argsSerialized[0]);
		args.redeem_eth_value = argsSerialized[1];
		
		//Initialize Arrays
		length = (argsSerialized[2] & 0xFFFFFFFFFFFFFFFF);
		if (length > 0) args.input_tx = new UTXO.Input[](length);
		
		length = (argsSerialized[2] & (0xFFFFFFFFFFFFFFFF << 64)) >> 64;
		if (length > 0) args.output_tx = new UTXO.Output[](length);
		
		length = (argsSerialized[2] & (0xFFFFFFFFFFFFFFFF << 128)) >> 128;
		if (length > 0) args.I = new uint256[](length);
		
		length = (argsSerialized[2] & (0xFFFFFFFFFFFFFFFF << 192)) >> 192;
		if (length > 0) args.signature = new uint256[](length);
		
		//Check input length again
		//In the first case, all args are provided explicitly
		length = 3 + args.input_tx.length*4 + args.output_tx.length*9 + args.I.length + args.signature.length;
		index = 3;
		if (argsSerialized.length >= length) {
			//Assemble the rest of args
			for (i = 0; i < args.input_tx.length; i++) {
				args.input_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
				args.input_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
				index = index + 4;
			}
		}
		else {
			//In the 2nd case, input_tx values are implicit.  This makes sense, because usually these will be supplied by the contract
			//Subtract of 2 for each args.input_tx.value[i]
			length -= args.input_tx.length*2;
			if (argsSerialized.length >= length) {
				//Assemble the rest of args (with implicit args.input_tx.value[i])
				index = 6;
				for (i = 0; i < args.input_tx.length; i++) {
					args.input_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
					//No check for args.input_tx.value[i]
					index = index + 2;
				}
			}
			else {
				revert(); //Not enough arguments
			}
		}
		
		//In either case, all other arguments must be supplied explicitly
		for (i = 0; i < args.output_tx.length; i++) {
			args.output_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
			args.output_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
			args.output_tx[i].dhe_point = [argsSerialized[index+4], argsSerialized[index+5]];
			args.output_tx[i].encrypted_data = [argsSerialized[index+6], argsSerialized[index+7], argsSerialized[index+8]];
			index = index + 9;
		}
		
		for (i = 0; i < args.I.length; i++) {
			args.I[i] = argsSerialized[index+i];
		}
		index = index + args.I.length;
		
		for (i = 0; i < args.signature.length; i++) {
			args.signature[i] = argsSerialized[index+i];
		}
	}
	
	//Decomposes Ring CT Tx Args struct into uint256 array
	function Serialize(Data args)
		internal pure returns (uint256[] argsSerialized)
	{
		argsSerialized = new uint256[](3 + args.input_tx.length*4 + args.output_tx.length*9 + args.I.length + args.signature.length);
		
		argsSerialized[0] = uint256(args.redeem_eth_address);
		argsSerialized[1] = args.redeem_eth_value;
		
		argsSerialized[2] = (args.input_tx.length & 0xFFFFFFFFFFFFFFFF);
		argsSerialized[2] |= (args.output_tx.length & 0xFFFFFFFFFFFFFFFF) << 64;
		argsSerialized[2] |= (args.I.length & 0xFFFFFFFFFFFFFFFF) << 128;
		argsSerialized[2] |= (args.signature.length & 0xFFFFFFFFFFFFFFFF) << 192;
		
		uint256 i;
		uint256 index = 3;
		for (i = 0; i < args.input_tx.length; i++) {
			argsSerialized[index] = args.input_tx[i].pub_key[0];
			argsSerialized[index+1] = args.input_tx[i].pub_key[1];
			argsSerialized[index+2] = args.input_tx[i].value[0];
			argsSerialized[index+3] = args.input_tx[i].value[1];
			index = index + 4;
		}
		
		for (i = 0; i < args.output_tx.length; i++) {
			argsSerialized[index] = args.output_tx[i].pub_key[0];
			argsSerialized[index+1] = args.output_tx[i].pub_key[1];
			argsSerialized[index+2] = args.output_tx[i].value[0];
			argsSerialized[index+3] = args.output_tx[i].value[1];
			argsSerialized[index+4] = args.output_tx[i].dhe_point[0];
			argsSerialized[index+5] = args.output_tx[i].dhe_point[1];
			argsSerialized[index+6] = args.output_tx[i].encrypted_data[0];
			argsSerialized[index+7] = args.output_tx[i].encrypted_data[1];
			argsSerialized[index+8] = args.output_tx[i].encrypted_data[2];
			index = index + 9;
		}
		
		for (i = 0; i < args.I.length; i++) {
		    argsSerialized[index+i] = args.I[i];
		}
		index = index + args.I.length;
		
		for (i = 0; i < args.signature.length; i++) {
		    argsSerialized[index+i] = args.signature[i];
		}
	}
	
	function EchoTest(uint256[] argsSerialized) public pure returns (uint256[]) {
	    return Serialize(Deserialize(argsSerialized));
	}
}

library UTXO {
    //Represents an input unspent transaction output (candidate for spending)
    struct Input {
        uint256[2] pub_key;
        uint256[2] value;
    }
    
    //Represents an output unspent transaction output (new stealth transaction output)
    struct Output {
        uint256[2] pub_key;
        uint256[2] value;
        uint256[2] dhe_point;
        uint256[3] encrypted_data;
    }
}

