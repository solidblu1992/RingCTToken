pragma solidity ^0.4.13;

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

contract MLSAGVerify {	
	//----------------------------
	//	MSLAG Algorithms
	//----------------------------

    //Non-linkable Ring Signature Functions
    function RingHashFunction(uint256 msgHash, uint256[2] point) public view returns (uint256 h);
    function StartRing_NoHash(uint256 alpha) public constant returns (uint256[2] Pout);
    function StartRing(uint256 msgHash, uint256 alpha) public constant returns (uint256 ckp);
    function CalculateRingSegment_NoHash(uint256 ck, uint256 sk, uint256[2] P) public constant returns (uint256[2] Pout);
    function CalculateRingSegment(uint256 msgHash, uint256 ck, uint256 sk, uint256[2] P) public constant returns (uint256 ckp);
	
    //CompleteRing = (alpha - c*xk) % N
    //Note: usable in both linkable and non-linkable rings.
    function CompleteRing(uint256 alpha, uint256 c, uint256 xk) public view returns (uint256 s);
    
    //Linkable Ring Signature Functions
    function LinkableRingHashFunction(uint256 msgHash, uint256[2] left, uint256[2] right) public view returns (uint256 h);
    function CalculateKeyImageFromPrivKey(uint256 pk) public constant returns (uint256[2] I);
    function StartLinkableRing_NoHash(uint256 alpha, uint256[2] P) public constant returns (uint256[2] Lout, uint256[2] Rout);
    function StartLinkableRing(uint256 msgHash, uint256 alpha, uint256[2] P) public constant returns (uint256 ckp);
    function CalculateLinkableRingSegment_NoHash(uint256 ck, uint256 sk, uint256[2] P, uint256[2] I) public constant returns (uint256[2] Lout, uint256[2] Rout);
    function CalculateLinkableRingSegment(uint256 msgHash, uint256 ck, uint256 sk, uint256[2] P, uint256[2] I) public constant returns (uint256 ckp);

    //Calculate keccak256 of given array
    function Keccak256OfArray(uint256[] array) public pure returns (uint256 out);
	
	//----------------------------
	//	MSLAG Verification Functions
	//----------------------------
	
    //Verify SAG (Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //P = {P1x, P1y, P2x, P2y, ..., Pnx, Pny}
    //signature = {c1, s1, s2, ... , sn}
    function VerifySAG(uint256 msgHash, uint256[] P, uint256[] signature) public constant returns (bool success);
	
    //Verify SAG (Spontaneous Ad-hoc Group Signature, non-linkable)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //P = {P1, P2, ... , Pn}
    //signature = {c1, s1, s2, ... , sn}
    function VerifySAG_Compressed(uint256 msgHash, uint256[] P, uint256[] signature) public constant returns (bool success);
    
    //Verify LSAG (Linkable Spontaneous Ad-hoc Group Signature)
    //msgHash = hash of message signed by ring signature
    //I = {Ix, Iy}
    //P = {P1x, P1y, P2x, P2y, ..., Pnx, Pny}
    //signature = {c1, s1, s2, ..., sn}
    function VerifyLSAG(uint256 msgHash, uint256[] I, uint256[] P, uint256[] signature) public constant returns (bool success);
	
    //Verify LSAG (Linkable Spontaneous Ad-hoc Group Signature)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //I = key image (compressed EC point)
    //P = {P1, P2, ... , Pn}
    //signature = {c1, s1, s2, ... , sn}
    function VerifyLSAG_Compressed(uint256 msgHash, uint256 I, uint256[] P, uint256[] signature) public constant returns (bool success);
	
    //Verify MSAG (Multilayered Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //P = { P11x, P11y, P12x, P12y, ..., P1mx, P1my,
    //      P21x, P21y, P22x, P22y, ..., P2mx, P2my,
    //      Pn1x, P1ny, Pn2x, P2ny, ..., Pnmx, Pnmy }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMSAG(uint256 m, uint256 msgHash, uint256[] P, uint256[] signature) public constant returns (bool success);
    
    //Verify MSAG (Multilayered Spontaneous Ad-hoc Group Signature, non-linkable)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //P = { P11, P12, ..., P1m,
    //      P21, P22, ..., P2m,
    //      Pn1, Pn2, ..., Pnm }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMSAG_Compressed(uint256 m, uint256 msgHash, uint256[] P, uint256[] signature) public constant returns (bool success);
    
    //Verify MLSAG (Multilayered Linkable Spontaneous Ad-hoc Group Signature)
    //msgHash = hash of message signed by ring signature
    //I = { I1x, I1y, I2x, I2y, ..., Imx, Imy }
    //P = { P11x, P11y, P12x, P12y, ..., P1mx, P1my,
    //      P21x, P21y, P22x, P22y, ..., P2mx, P2my,
    //      Pn1x, P1ny, Pn2x, P2ny, ..., Pnmx, Pnmy }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMLSAG(uint256 msgHash, uint256[] I, uint256[] P, uint256[] signature) public constant returns (bool success);
    
    //Verify MLSAG (Multilayered Linkable Spontaneous Ad-hoc Group Signature)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //I = { I1, I2, ..., Im }
    //P = { P11, P12, ..., P1m,
    //      P21, P22, ..., P2m,
    //      Pn1, Pn2, ..., Pnm }
    //signature = {c1, s11, s12, ..., s1m, s21, s22, ..., s2m, ..., sn1, sn2, ..., snm}
    function VerifyMLSAG_Compressed(uint256 msgHash, uint256[] I, uint256[] P, uint256[] signature) public constant returns (bool success);
}

contract MLSAGVerifyInterface is Debuggable {
    //Prerequisite Contract(s)
	MLSAGVerify mlsagVerify;
	
	event ContractAddressChanged (string _name, address _new);
	
	//Prerequisite Contract Meta Functions
	function MLSAGVerify_GetAddress() public constant returns (address) {
		return address(mlsagVerify);
	}
	
	function MLSAGVerify_GetCodeSize() public constant returns (uint) {
	    uint code_size;
		address addr = MLSAGVerify_GetAddress();
		assembly {
		    code_size := extcodesize(addr)
		}
		
		return code_size;
	}
	
	function MLSAGVerify_ChangeAddress(address mlsagVerifyAddr) public ownerOnly {
		//Check code size at old address (only allow reassignment on contract deletion)
		//require(MLSAGVerify_GetCodeSize() == 0);
		
		mlsagVerify = MLSAGVerify(mlsagVerifyAddr);
		emit ContractAddressChanged("MLSAGVerify", mlsagVerifyAddr);
	}
	
	modifier requireMLSAGVerify {
	    require(MLSAGVerify_GetCodeSize() > 0);
	    _;
	}

	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address mlsagVerifyAddr) public {
	    MLSAGVerify_ChangeAddress(mlsagVerifyAddr);
	}
}

contract RingCTTxVerify is ECMathInterface, MLSAGVerifyInterface {
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ecMathAddr, address mlsagVerifyAddr) ECMathInterface(ecMathAddr) MLSAGVerifyInterface(mlsagVerifyAddr) public { }
	
	//Struct for reducing stack length
    struct Variables {
        uint256 m;              //Number of keys (# of rings)
        uint256 n;              //Number of ring members (per ring)
        uint256 i;              //for use in "for" loop (i = {0, ..., m})
        uint256 j;              //for use in "for" loop (j = {0, ..., n})
        uint256 index;          //General purpose uint256 for picking index of arrays
        uint256[2] point1;      //Expanded EC Point for general purpose use
        uint256[2] point2;      //Expanded EC Point for general purpose use
        uint256[2] point3;      //Expanded EC Point for general purpose use
        uint256[2] keyImage;    //Expanded EC Point representing key image
    }
	
    //Constructs full MLSAG for Ring CT Transaction and Verifies
	function ValidateRingCTTx(uint256[] argsSerialized)
		public view requireECMath requireMLSAGVerify returns (bool)
	{
		//Deserialize arguments
		RingCTTxStruct.Data memory args = RingCTTxStruct.Deserialize(argsSerialized);
	
		//Need at least one destination
        if (args.output_tx.length == 0) return false;
        
        //Check other array lengths
        if (args.I.length % 2 != 0) return false;
        
        Variables memory v;
        v.m = (args.I.length / 2);
		
		if (v.m < 2) return false;
		v.m = v.m - 1;
        
        if (args.input_tx.length % v.m != 0) return false;
        v.n = args.input_tx.length / v.m;
        
		//Create last two columns of MLSAG public key set (sigma{input_pub_keys} + sigma{input_commitments} - sigma{output_commitments}
		//Calculate negative of total destination commitment
		//Note, here keyImage is used, but this is just because another EC point in memory is needed (not an actual key image)
        v.keyImage = args.output_tx[v.i].value;
        for (v.i = 1; v.i < args.output_tx.length; v.i++) {
            v.keyImage = ecMath.Add(v.keyImage, args.output_tx[v.i].value);
        }
		
		//Withdrawal only
		if (args.redeem_eth_value > 0) {
			//Add unmasked value as a commitment
			v.point1 = ecMath.MultiplyH(args.redeem_eth_value);
			v.keyImage = ecMath.Add(v.keyImage, v.point1);
		}
		
        v.keyImage = ecMath.Negate(v.keyImage);
		
		//Assemble right column of MLSAG array
		uint256[] memory P = new uint256[](2*v.n*(v.m+1));
		for (v.i = 0; v.i < v.n; v.i++) {
			//Sum input public keys and their commitments			
			for (v.j = 0; v.j < v.m; v.j++) {
				//Retreive public key and commitment
				v.index = v.m*v.i+v.j;
				v.point1 = args.input_tx[v.index].pub_key;
				v.point2 = args.input_tx[v.index].value;
				if (v.point2[0] == 0 && v.point2[1] == 0) return false; //No commitment found!
				
				//Add public key to P
			    (P[2*(v.index+v.i)], P[2*(v.index+v.i)+1]) = (v.point1[0], v.point1[1]);
				
				//Sum pub key and commitment, eventually storing in last column of points (in P[])
				if (v.j == 0) {
					v.point3 = ecMath.Add(v.point1, v.point2);
				}
				else {
					v.point3 = ecMath.Add(v.point3, v.point1);
					v.point3 = ecMath.Add(v.point3, v.point2);
				}
			}
			
			//Add negated output commitments
			v.point3 = ecMath.Add(v.point3, v.keyImage);
			
			//Store point 3 into P (summation columns)
			v.index = (v.m+1)*(v.i+1)-1;
			(P[2*v.index], P[2*v.index+1]) = (v.point3[0], v.point3[1]);
		}
        
        //Verify ring signature (MLSAG)
		if (args.redeem_eth_value > 0)
			return mlsagVerify.VerifyMLSAG(HashWithdrawMsg(args.redeem_eth_address, args.redeem_eth_value, args.output_tx), args.I, P, args.signature);
        else
            return mlsagVerify.VerifyMLSAG(HashSendMsg(args.output_tx), args.I, P, args.signature);
        
		return true;
	}

    //Verifies range proof for given commitment.  Returns if commitment is proven to be positive
    function VerifyBorromeanRangeProof(uint256[] argsSerialized)
        public view requireECMath requireMLSAGVerify returns (bool success)
    {
		//Deserialize arguments
		BorromeanRangeProofStruct.Data memory args = BorromeanRangeProofStruct.Deserialize(argsSerialized);
	
        //Get number of bits to prove
        if (args.bit_commits.length % 2 != 0) return false;
        uint256 bits = (args.bit_commits.length / 2);
        if (bits == 0) return false;
        
        //Impose limits on inputs in order to avoid values greater than Ncurve // 2
        if (bits > 64) return false;
        
        //Check for proper signature size
        if (args.signature.length != (4*bits+1)) return false;
        
        //Check that bitwise commitments add up to total commitment
        uint256 i;
        uint256[2] memory temp1;
        temp1 = [args.bit_commits[0], args.bit_commits[1]];
        for (i = 1; i < bits; i++) {
            temp1 = ecMath.Add(temp1, [args.bit_commits[2*i], args.bit_commits[2*i+1]]);
        }
		
        if ( (args.total_commit[0] != temp1[0]) || (args.total_commit[1] != temp1[1]) ) return false;
        
        //Build Public Keys for Signature Verification
        uint256[] memory P = new uint256[](8*bits);
        uint256[2] memory temp2;
        for (i = 0; i < bits; i++) {
            //Store bitwise commitment
            temp1 = [args.bit_commits[2*i], args.bit_commits[2*i+1]];
            (P[2*i], P[2*i+1]) = (temp1[0], temp1[1]);
            
            //Calculate -(4**bit)*H
            temp2 = ecMath.MultiplyH(4**i);
            temp2 = ecMath.Negate(temp2);
            
            //Calculate 1st counter commitment: C' = C - (4**bit)*H
            temp1 = ecMath.Add(temp1, temp2);
            (P[2*(i+bits)], P[2*(i+bits)+1]) = (temp1[0], temp1[1]);
            
            //Calculate 2nd counter commitment: C'' = C - 2*(4**bit)*H
            temp1 = ecMath.Add(temp1, temp2);
            (P[2*(i+2*bits)], P[2*(i+2*bits)+1]) = (temp1[0], temp1[1]);
            
            //Calculate 3rd counter commitment: C''' = C - 3*(4**bit)*H
            temp1 = ecMath.Add(temp1, temp2);
            (P[2*(i+3*bits)], P[2*(i+3*bits)+1]) = (temp1[0], temp1[1]);
        }
        
        //Verify Signature
        success = mlsagVerify.VerifyMSAG(bits, ecMath.CompressPoint(args.total_commit), P, args.signature);
    }
    
    //Utility Functions
    function HashSendMsg(UTXO.Output[] output_tx)
        internal pure returns (uint256 msgHash)
    {
        msgHash = output_tx.length;
        
        for (uint256 i = 0; i < output_tx.length; i++) {
            msgHash = uint256(keccak256(msgHash, output_tx[i].pub_key[0], output_tx[i].pub_key[1],
                                    output_tx[i].value[0], output_tx[i].value[1],
                                    output_tx[i].dhe_point[0], output_tx[i].dhe_point[1],
                                    output_tx[i].encrypted_data[0], output_tx[i].encrypted_data[1], output_tx[i].encrypted_data[2]));
        }
    }
	
	function HashWithdrawMsg(address ethAddress, uint256 value, UTXO.Output[] output_tx)
		internal pure returns (uint256 msgHash)
	{
        msgHash = HashSendMsg(output_tx);
        msgHash = uint256(keccak256(msgHash, ethAddress, value));
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

