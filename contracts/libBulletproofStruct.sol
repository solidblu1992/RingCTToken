pragma solidity ^0.4.24;

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