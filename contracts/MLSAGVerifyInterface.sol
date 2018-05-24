pragma solidity ^0.4.22;

import "./Debuggable.sol";

//Contract interface for calling MLSAGVerify contract stored else-where on chain
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

//Example Interface Contract
//This contract provieds useful functions for utilizing a MLSAGVerify contract stored else-where on chain
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