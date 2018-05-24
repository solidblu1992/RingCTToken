pragma solidity ^0.4.22;

library BorromeanRangeProofStruct {
	//Structure for VerifyPCRangeProof() arguments
	struct Data {
		uint256[2] total_commit;
		uint256 power10;
		uint256 offset;
		uint256[] bit_commits;
		uint256[] signature;
	}
	
	//Creates Borromean Range Proof Args struct from uint256 array
	function Deserialize(uint256[] argsSerialized)
		internal pure returns (Data args)
	{
		//Check input length, need at least 6 arguments - assuming all variable arrays are zero length and only store the size
		require(argsSerialized.length >= 6);
		
		//Deserialize
		uint256 i;
		uint256 index;
		uint256 length;
		args.total_commit = [argsSerialized[0], argsSerialized[1]];
		args.power10 = argsSerialized[2];
		args.offset = argsSerialized[3];
		
		//Initialize Arrays
		length = argsSerialized[4];
		if (length > 0) args.bit_commits = new uint256[](length);
		
		length = argsSerialized[5];
		if (length > 0) args.signature = new uint256[](length);
		
		//Check input length again
		require(argsSerialized.length >= (6 + args.bit_commits.length + args.signature.length));
		
		//Assemble the rest of args
		index = 6;
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
		argsSerialized = new uint256[](6 + args.bit_commits.length + args.signature.length);
		
		argsSerialized[0] = args.total_commit[0];
		argsSerialized[1] = args.total_commit[1];
		argsSerialized[2] = args.power10;
		argsSerialized[3] = args.offset;
		argsSerialized[4] = args.bit_commits.length;
		argsSerialized[5] = args.signature.length;
		
		uint256 i;
		uint256 index = 6;		
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