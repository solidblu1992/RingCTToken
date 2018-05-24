pragma solidity ^0.4.22;

import "./Debuggable.sol";
import "./ECMathInterface.sol";
import "./MLSAGVerifyInterface.sol";
import "./libUTXO.sol";
import "./libBorromeanRangeProofStruct.sol";
import "./libRingCTTxStruct.sol";

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
	
    //Constructs full MLSAG for Ring CT Transaction and Verifes
	function ValidateRingCTTx(RingCTTxStruct.Data args)
		internal view requireECMath requireMLSAGVerify returns (bool)
	{
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
	
	//Serialized version of ValidateRingCTTx.  This version does not use structs so that it can be called publicly.
	function ValidateRingCTTx(uint256[] argsSerialized)
	    public view returns (bool)
	{	    
	    return ValidateRingCTTx(RingCTTxStruct.Deserialize(argsSerialized));
	}
	
    //Verifies range proof for given commitment.  Returns if commitment is proven to be positive
    function VerifyBorromeanRangeProof(BorromeanRangeProofStruct.Data args)
        internal view requireECMath requireMLSAGVerify returns (bool success)
    {
        //Get number of bits to prove
        if(args.bit_commits.length % 2 != 0) return false;
        uint256 bits = (args.bit_commits.length / 2);
        if (bits == 0) return false;
        
        //Impose limits on inputs in order to avoid values greater than Ncurve // 2
        if (args.power10 > 35) return false;
        if (args.offset > (ecMath.GetNCurve() / 4)) return false;
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
		
		if (args.offset > 0) {
			temp1 = ecMath.AddMultiplyH(temp1, args.offset);
        }
		
        if ( (args.total_commit[0] != temp1[0]) || (args.total_commit[1] != temp1[1]) ) return false;
        
        //Build Public Keys for Signature Verification
        uint256[] memory P = new uint256[](8*bits);
        uint256[2] memory temp2;
        for (i = 0; i < bits; i++) {
            //Store bitwise commitment
            temp1 = [args.bit_commits[2*i], args.bit_commits[2*i+1]];
            (P[2*i], P[2*i+1]) = (temp1[0], temp1[1]);
            
            //Calculate -(4**bit)*(10**power10)*H
            temp2 = ecMath.MultiplyH((4**i)*(10**args.power10));
            temp2 = ecMath.Negate(temp2);
            
            //Calculate 1st counter commitment: C' = C - (4**bit)*(10**power10)*H
            temp1 = ecMath.Add(temp1, temp2);
            (P[2*(i+bits)], P[2*(i+bits)+1]) = (temp1[0], temp1[1]);
            
            //Calculate 2nd counter commitment: C'' = C - 2*(4**bit)*(10**power10)*H
            temp1 = ecMath.Add(temp1, temp2);
            (P[2*(i+2*bits)], P[2*(i+2*bits)+1]) = (temp1[0], temp1[1]);
            
            //Calculate 3rd counter commitment: C''' = C - 3*(4**bit)*(10**power10)*H
            temp1 = ecMath.Add(temp1, temp2);
            (P[2*(i+3*bits)], P[2*(i+3*bits)+1]) = (temp1[0], temp1[1]);
        }
        
        //Verify Signature
        success = mlsagVerify.VerifyMSAG(bits, ecMath.CompressPoint(args.total_commit), P, args.signature);
    }
    
    //Serialized version of VerifyBorromeanRangeProof.  This version does not use structs so that it can be called publicly.
	function VerifyBorromeanRangeProof(uint256[] argsSerialized)
	    public view returns (bool)
	{	    
	    return VerifyBorromeanRangeProof(BorromeanRangeProofStruct.Deserialize(argsSerialized));
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
