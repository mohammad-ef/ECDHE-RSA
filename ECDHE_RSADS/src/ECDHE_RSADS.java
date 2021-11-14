import java.security.NoSuchAlgorithmException;

public class ECDHE_RSADS {
	public static void main(String []args) throws NoSuchAlgorithmException {
		ECDHE_RSA alice=new ECDHE_RSA();
		ECDHE_RSA bob=new ECDHE_RSA();
		System.out.println("------------DSA key generation for alice-------------");
		alice.DSA_key_generation(alice);
		System.out.println("------------DSA key generation for bob-------------");
		bob.DSA_key_generation(alice);
		System.out.println("------------ECDSA key generation for alice-------------");
		alice.ECDSA_key_generation(alice);
		System.out.println("------------ECDSA key generation for bob-------------");
		bob.ECDSA_key_generation(bob);
		System.out.println("---------DH_Key_Generation for alice----------");
		alice.DH_key_generation(alice);
		System.out.println("-----------------------------------------------");
		System.out.println("-----------DH_Key_Generation for bob----------");
		bob.DH_key_generation(bob);
		System.out.println("-----------------------------------------------");
		System.out.println("---------RSA_Key_Generation for alice----------");
		alice.RSA_Key_Generation();
		System.out.println("-----------------------------------------------");
		System.out.println("----------RSA_Key_Generation for bob-----------");
		bob.RSA_Key_Generation();
		System.out.println("-----------------------------------------------");
		boolean alice_validation_Signature = false;
		boolean bob_validation_Signature = false;
		/*
		boolean DSA_alice_validation_Signature = false;
		boolean ECDSA_alice_validation_Signature = false;
		boolean ECDSA_bob_validation_Signature = false;
		boolean DSA_bob_validation_Signature = false;
		*/
		try {
			alice.public_parameter_hash = alice.sha1(alice.DH_public_parameter);
			System.out.println("--------------RSA alice signs--------------");
			alice.DH_singed_hash = alice.sign(alice.public_parameter_hash,alice.RSA_private_key, alice.n);
			/*
			System.out.println("-----------DSA alice signs--------------");
			alice.DSA_DH_singed_hash = alice.DSA_sign(alice.public_parameter_hash,alice.DSA_parameter);
			System.out.println("-----------ECDSA alice signs--------------");
			alice.ECDSA_DH_singed_hash = alice.ECDSA_sign(alice.public_parameter_hash,alice);*/
			System.out.println('\n'+"--------------RSA bob Verification------------");
			alice_validation_Signature=bob.encrypt_Verification( alice.DH_singed_hash,alice.DH_public_parameter, alice.RSA_public_key, alice.n) ;
			/*
			System.out.println('\n'+"-------------DSA bob Verification------------");
			DSA_alice_validation_Signature=bob.DSA_Verification( alice.DSA_DH_singed_hash,alice.DH_public_parameter, alice.DSA_parameter) ;
			System.out.println('\n'+"-------------ECDSA bob Verification------------");
			ECDSA_alice_validation_Signature=bob.ECDSA_Verification( alice.ECDSA_DH_singed_hash,alice.DH_public_parameter,alice) ;*/
			
			if (alice_validation_Signature/* && DSA_alice_validation_Signature && ECDSA_alice_validation_Signature*/) 
				System.out.println("alice's Signature is ok");
			else
				System.out.println("alice's Signature is Not ok");
			
			System.out.println("-----------------------------------------------");
			bob.public_parameter_hash = bob.sha1(bob.DH_public_parameter);
			System.out.println("-------------RSA bob signs--------------");
			bob.DH_singed_hash = bob.sign(bob.public_parameter_hash,bob.RSA_private_key, bob.n);
			/*
			System.out.println("-----------DSA bob signs--------------");
			bob.DSA_DH_singed_hash = bob.DSA_sign(bob.public_parameter_hash,bob.DSA_parameter);
			System.out.println("-----------ECDSA bob signs--------------");
			bob.ECDSA_DH_singed_hash = bob.ECDSA_sign(bob.public_parameter_hash,bob);*/
			System.out.println('\n'+"--------------alice Verification------------");
			bob_validation_Signature=alice.encrypt_Verification( bob.DH_singed_hash,bob.DH_public_parameter, bob.RSA_public_key, bob.n);
			/*
			System.out.println('\n'+"-------------DSA bob Verification------------");
			DSA_bob_validation_Signature=alice.DSA_Verification( bob.DSA_DH_singed_hash,bob.DH_public_parameter, bob.DSA_parameter) ;
			System.out.println('\n'+"-------------ECDSA bob Verification------------");
			ECDSA_bob_validation_Signature=alice.ECDSA_Verification( bob.ECDSA_DH_singed_hash,bob.DH_public_parameter,bob);*/
			
			if(bob_validation_Signature/* && DSA_bob_validation_Signature && ECDSA_bob_validation_Signature*/)
				System.out.println("bob's Signature is ok");
			else
				System.out.println("bob's Signature is Not ok");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("-----------------------------------------------");
		System.out.println("------------share key generation--------------");
		if (alice_validation_Signature && bob_validation_Signature/* && ECDSA_bob_validation_Signature 
				&& DSA_bob_validation_Signature && DSA_alice_validation_Signature && ECDSA_alice_validation_Signature*/) {
			alice.share_key(bob, alice.DH_private_key);
			System.out.println();
			bob.share_key(alice,bob.DH_private_key);
		}else
			System.out.println("something went wrong");
	}
}
