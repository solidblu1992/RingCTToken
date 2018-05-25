pragma solidity ^0.4.24;

import "./Debuggable.sol";
import "./ECMathInterface.sol";

contract MLSAGVerify is ECMathInterface {
	//Contstructor Function - Initializes Prerequisite Contract(s)
	constructor(address ecMathAddr) ECMathInterface(ecMathAddr) public {}
    
    //Struct for reducing stack length
    struct Variables {
        uint256 m;              //Number of keys (# of rings)
        uint256 n;              //Number of ring members (per ring)
        uint256 i;              //for use in "for" loop (i = {0, ..., m})
        uint256 j;              //for use in "for" loop (j = {0, ..., n})
        uint256 ck;             //Current hash input for ring segment
        uint256 index;          //General purpose uint256 for picking index of arrays
        uint256[2] point1;      //Expanded EC Point for general purpose use
        uint256[2] point2;      //Expanded EC Point for general purpose use
        uint256[2] keyImage;    //Expanded EC Point representing key image
    }
    
    //Non-linkable Ring Signature Functions
    function RingHashFunction(uint256 msgHash, uint256[2] point)
        public view returns (uint256 h)
    {
        return uint256(keccak256(msgHash, point[0], point[1])) % ecMath.GetNCurve();
    }
    
    function StartRing_NoHash(uint256 alpha)
        public constant returns (uint256[2] Pout)
    {
        Pout = ecMath.Multiply(ecMath.GetG1(), alpha);
    }
    
    function StartRing(uint256 msgHash, uint256 alpha)
        public constant returns (uint256 ckp)
    {
        ckp = RingHashFunction(msgHash, StartRing_NoHash(alpha));
    }
    
    function CalculateRingSegment_NoHash(uint256 ck, uint256 sk, uint256[2] P)
        public constant returns (uint256[2] Pout)
    {
        uint256[2] memory temp;
        Pout = ecMath.Multiply(ecMath.GetG1(), sk);
        temp = ecMath.Multiply(P, ck);
        Pout = ecMath.Add(Pout, temp);
    }
    
    function CalculateRingSegment(uint256 msgHash, uint256 ck, uint256 sk, uint256[2] P)
        public constant returns (uint256 ckp)
    {
        uint256[2] memory temp;
        temp = CalculateRingSegment_NoHash(ck, sk, P);
        ckp = RingHashFunction(msgHash, temp);
    }
    
    //CompleteRing = (alpha - c*xk) % N
    //Note: usable in both linkable and non-linkable rings.
    function CompleteRing(uint256 alpha, uint256 c, uint256 xk)
        public view returns (uint256 s)
    {
        s = mulmod(c, xk, ecMath.GetNCurve());
        s = ecMath.GetNCurve() - s;
        s = addmod(alpha, s, ecMath.GetNCurve());
    }
    
    //Linkable Ring Signature Functions
    function LinkableRingHashFunction(uint256 msgHash, uint256[2] left, uint256[2] right)
        public view returns (uint256 h)
    {
        return uint256(keccak256(msgHash, left[0], left[1], right[0], right[1])) % ecMath.GetNCurve();
    }
    
    function CalculateKeyImageFromPrivKey(uint256 pk)
        public constant returns (uint256[2] I)
    {
        uint256[2] memory temp;
        temp = ecMath.Multiply(ecMath.GetG1(), pk);
        temp = ecMath.HashToPoint(temp);
        temp = ecMath.Multiply(temp, pk);
        I = temp;
    }
    
    function StartLinkableRing_NoHash(uint256 alpha, uint256[2] P)
        public constant returns (uint256[2] Lout, uint256[2] Rout)
    {
        Lout = ecMath.Multiply(ecMath.GetG1(), alpha);
        
        Rout = ecMath.HashToPoint(P);
        Rout = ecMath.Multiply(Rout, alpha);
    }
    
    function StartLinkableRing(uint256 msgHash, uint256 alpha, uint256[2] P)
        public constant returns (uint256 ckp)
    {
        uint256[2] memory left;
        uint256[2] memory right;
        (left, right) = StartLinkableRing_NoHash(alpha, P);
        ckp = LinkableRingHashFunction(msgHash, left, right);
    }
    
    function CalculateLinkableRingSegment_NoHash(uint256 ck, uint256 sk, uint256[2] P, uint256[2] I)
        public constant returns (uint256[2] Lout, uint256[2] Rout)
    {
        uint256[2] memory temp;
        Lout = ecMath.Multiply(ecMath.GetG1(), sk);
        temp = ecMath.Multiply(P, ck);
        Lout = ecMath.Add(Lout, temp);
        
        Rout = ecMath.HashToPoint(P);
        Rout = ecMath.Multiply(Rout, sk);
        temp = ecMath.Multiply(I, ck);
        Rout = ecMath.Add(Rout, temp);
    }
    
    function CalculateLinkableRingSegment(uint256 msgHash, uint256 ck, uint256 sk, uint256[2] P, uint256[2] I)
        public constant returns (uint256 ckp)
    {
        uint256[2] memory left;
        uint256[2] memory right;
        (left, right) = CalculateLinkableRingSegment_NoHash(ck, sk, P, I);
        ckp = LinkableRingHashFunction(msgHash, left, right);
    }
    
    //Calculate keccak256 of given array
    function Keccak256OfArray(uint256[] array)
        public pure returns (uint256 out)
    {
        uint256 len = array.length;
        uint256[1] memory temp;
        
        //Construct c1 (store in c[0])
    	assembly {
    	    let p := mload(0x40)
    	    mstore(p, add(mul(len, 0x20), 0x20)) //0x20 = 32; 32 bytes for array length + 32 bytes per uint256
    	    mstore(temp, keccak256(array, mload(p)))
    	}
    	
    	out = temp[0];
    }
    
	//----------------------------
	//MSLAG Verification Functions
	//----------------------------
	
    //Verify SAG (Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //P = {P1x, P1y, P2x, P2y, ..., Pnx, Pny}
    //signature = {c1, s1, s2, ... , sn}
    function VerifySAG(uint256 msgHash, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        //Check input array lengths
        Variables memory v;
        if (P.length % 2 != 0) return false;
        v.n = (P.length / 2);
        if (signature.length != (v.n+1)) return false;
        
        v.ck = signature[0];                            //extract c1
        for (v.i = 0; v.i < v.n; v.i++) {
            (v.point1[0], v.point1[1]) = (P[2*v.i], P[2*v.i+1]); //extract public key
            v.ck = CalculateRingSegment(msgHash, v.ck, signature[v.i+1], v.point1);
        }
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify SAG (Spontaneous Ad-hoc Group Signature, non-linkable)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //P = {P1, P2, ... , Pn}
    //signature = {c1, s1, s2, ... , sn}
    function VerifySAG_Compressed(uint256 msgHash, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        uint256[2] memory temp;
        uint256[] memory P_uncomp = new uint256[](P.length*2);
        
        for (uint256 i = 0; i < P.length; i++) {
            temp = ecMath.ExpandPoint(P[i]);
            P_uncomp[2*i] = temp[0];
            P_uncomp[2*i+1] = temp[1];
        }
        
        return VerifySAG(msgHash, P_uncomp, signature);
    }
    
    //Verify LSAG (Linkable Spontaneous Ad-hoc Group Signature)
    //msgHash = hash of message signed by ring signature
    //I = {Ix, Iy}
    //P = {P1x, P1y, P2x, P2y, ..., Pnx, Pny}
    //signature = {c1, s1, s2, ..., sn}
    function VerifyLSAG(uint256 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        //Check input array lengths
        Variables memory v;
        if (I.length != 2) return false;
        if (P.length % 2 != 0) return false;
        v.n = (P.length / 2);
        if (signature.length != (v.n+1)) return false;
        
        v.ck = signature[0];                   //extract c1
        (v.keyImage[0], v.keyImage[1]) = (I[0], I[1]);  //extract key image
        
        for (v.i = 0; v.i < v.n; v.i++) {
            (v.point1[0], v.point1[1]) = (P[2*v.i], P[2*v.i+1]); //extract public key
            v.ck = CalculateLinkableRingSegment(msgHash, v.ck, signature[v.i+1], v.point1, v.keyImage);
        }
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify LSAG (Linkable Spontaneous Ad-hoc Group Signature)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //I = key image (compressed EC point)
    //P = {P1, P2, ... , Pn}
    //signature = {c1, s1, s2, ... , sn}
    function VerifyLSAG_Compressed(uint256 msgHash, uint256 I, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        uint256[2] memory temp;
        uint256[] memory P_uncomp = new uint256[](P.length*2);
        uint256[] memory I_uncomp = new uint256[](2);
        
        uint256 i;
        for (i = 0; i < P.length; i++) {
            temp = ecMath.ExpandPoint(P[i]);
            P_uncomp[2*i] = temp[0];
            P_uncomp[2*i+1] = temp[1];
        }
        
        temp = ecMath.ExpandPoint(I);
        (I_uncomp[0], I_uncomp[1]) = (temp[0], temp[1]);
        
        return VerifyLSAG(msgHash, I_uncomp, P_uncomp, signature);
    }
    
    //Verify MSAG (Multilayered Spontaneous Ad-hoc Group Signature, non-linkable)
    //msgHash = hash of message signed by ring signature
    //P = { P11x, P11y, P12x, P12y, ..., P1mx, P1my,
    //      P21x, P21y, P22x, P22y, ..., P2mx, P2my,
    //      Pn1x, P1ny, Pn2x, P2ny, ..., Pnmx, Pnmy }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMSAG(uint256 m, uint256 msgHash, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        //Check input array lengths
        Variables memory v;
        v.m = m;
        if (P.length % (2*v.m) != 0) return false;
        
        v.n = P.length / (2*v.m);
        if (signature.length != (v.m*v.n+1)) return false;
        
        //Allocate array for calculating c1
        uint256[] memory c = new uint256[](2*v.m+1);
        c[0] = msgHash;
        
        for (v.i = 0; v.i < v.m; v.i++) {
            v.ck = signature[0];                //extract c1
            
            //Calculate (n-1) ring segments (output scalar ck)
            for (v.j = 0; v.j < (v.n-1); v.j++) {
                v.index = v.m*v.j + v.i;
                (v.point1[0], v.point1[1]) = (P[2*v.index], P[2*v.index+1]); //extract public key
                v.ck = CalculateRingSegment(msgHash, v.ck, signature[v.index+1], v.point1);
            }
            
            //Calculate last ring segment (output EC point input for c1 calculation)
            v.index = v.m*(v.n-1) + v.i;
            (v.point1[0], v.point1[1]) = (P[2*v.index], P[2*v.index+1]); 
            v.point1 = CalculateRingSegment_NoHash(v.ck, signature[v.index+1], v.point1);
            
            //Store input to c1 calculation
            v.index = v.i*2+1;
            c[v.index] = v.point1[0];
            c[v.index+1] = v.point1[1];
        }
        
        //Calculate c1 from c point array = {msgHash, P1x, P1y, P2x, P2y, , ... , Pmx, Pmy}
        v.ck = Keccak256OfArray(c);
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify MSAG (Multilayered Spontaneous Ad-hoc Group Signature, non-linkable)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //P = { P11, P12, ..., P1m,
    //      P21, P22, ..., P2m,
    //      Pn1, Pn2, ..., Pnm }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMSAG_Compressed(uint256 m, uint256 msgHash, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        uint256[2] memory temp;
        uint256[] memory P_uncomp = new uint256[](P.length*2);
        
        uint256 i;
        for (i = 0; i < P.length; i++) {
            temp = ecMath.ExpandPoint(P[i]);
            P_uncomp[2*i] = temp[0];
            P_uncomp[2*i+1] = temp[1];
        }
        
        return VerifyMSAG(m, msgHash, P_uncomp, signature);
    }
    
    //Verify MLSAG (Multilayered Linkable Spontaneous Ad-hoc Group Signature)
    //msgHash = hash of message signed by ring signature
    //I = { I1x, I1y, I2x, I2y, ..., Imx, Imy }
    //P = { P11x, P11y, P12x, P12y, ..., P1mx, P1my,
    //      P21x, P21y, P22x, P22y, ..., P2mx, P2my,
    //      Pn1x, P1ny, Pn2x, P2ny, ..., Pnmx, Pnmy }
    //signature = {c1,  s11, s12, ..., s1m,
    //                  s21, s22, ..., s2m,
    //                  sn1, sn2, ..., snm  }
    function VerifyMLSAG(uint256 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        //Check input array lengths
        Variables memory v;
        if(I.length % 2 != 0) return false;
        v.m = (I.length / 2);
        if (P.length % (2*v.m) != 0) return false;
        
        v.n = P.length / (2*v.m);
        if (signature.length != (v.m*v.n+1)) return false;
        
        //Allocate array for calculating c1
        uint256[] memory c = new uint256[](4*v.m+1);
        c[0] = msgHash;
        
        for (v.i = 0; v.i < v.m; v.i++) {
            v.ck = signature[0];        //extract c1
            v.keyImage = [I[2*v.i], I[2*v.i+1]]; //extract key image
            
            //Calculate (n-1) ring segments (output scalar ck)
            for (v.j = 0; v.j < (v.n-1); v.j++) {
                v.index = v.m*v.j + v.i;
                v.point1 = [P[2*v.index], P[2*v.index+1]]; //extract public key
                v.ck = CalculateLinkableRingSegment(msgHash, v.ck, signature[v.index+1], v.point1, v.keyImage);
            }
            
            //Calculate last ring segment (output EC point input for c1 calculation)
            v.index = v.m*(v.n-1) + v.i;
            v.point1 = [P[2*v.index], P[2*v.index+1]]; //extract public key
            (v.point1, v.point2) = CalculateLinkableRingSegment_NoHash(v.ck, signature[v.index+1], v.point1, v.keyImage);
            
            //Store input to c1 calculation
            v.index = v.i*4+1;
            c[v.index] = v.point1[0];
            c[v.index+1] = v.point1[1];
            c[v.index+2] = v.point2[0];
            c[v.index+3] = v.point2[1];
        }
        
        //Calculate c1 from c point array = {msgHash, L1x, L1y, R1x, R1y, L2x, L2y, R2x, R2y, ... , Lmx, Lmy, Rmx, Rmy}
        v.ck = Keccak256OfArray(c);
        
        //See if c1 matches the original c1
        success = (v.ck == signature[0]);
    }
    
    //Verify MLSAG (Multilayered Linkable Spontaneous Ad-hoc Group Signature)
    //Using compressed EC points
    //msgHash = hash of message signed by ring signature
    //I = { I1, I2, ..., Im }
    //P = { P11, P12, ..., P1m,
    //      P21, P22, ..., P2m,
    //      Pn1, Pn2, ..., Pnm }
    //signature = {c1, s11, s12, ..., s1m, s21, s22, ..., s2m, ..., sn1, sn2, ..., snm}
    function VerifyMLSAG_Compressed(uint256 msgHash, uint256[] I, uint256[] P, uint256[] signature)
        public constant returns (bool success)
    {
        uint256[2] memory temp;
        uint256[] memory P_uncomp = new uint256[](P.length*2);
        uint256[] memory I_uncomp = new uint256[](I.length*2);
        
        uint256 i;
        for (i = 0; i < P.length; i++) {
            temp = ecMath.ExpandPoint(P[i]);
            P_uncomp[2*i] = temp[0];
            P_uncomp[2*i+1] = temp[1];
        }
        
        for (i = 0; i < I.length; i++) {
            temp = ecMath.ExpandPoint(I[i]);
            I_uncomp[2*i] = temp[0];
            I_uncomp[2*i+1] = temp[1];
        }
        
        return VerifyMLSAG(msgHash, I_uncomp, P_uncomp, signature);
    }
}

