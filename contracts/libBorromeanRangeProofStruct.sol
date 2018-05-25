pragma solidity ^0.4.24;

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