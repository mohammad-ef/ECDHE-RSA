import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class ECDHE_RSA {
	BigInteger n;
	BigInteger RSA_public_key;
	BigInteger RSA_private_key;
	
	BigInteger p=new BigInteger("6277101735386680763835789423207666416083908700390324961279");
	BigInteger b=new BigInteger("2455155546008943817740293915197451784769108058161191238065");
	BigInteger x=new BigInteger("602046282375688656758213480587526111916698976636884684818");
	BigInteger y=new BigInteger("174050332293622031404857552280219410364023488927386650641");
	BigInteger order=new BigInteger("6277101735386680763835789423176059013767194773182842284081");
	
	BigInteger DH_private_key;
	BigInteger DH_public_parameter[]=new BigInteger[3];
	BigInteger public_parameter_hash;
	BigInteger DH_singed_hash;
	
	BigInteger  DSA_DH_singed_hash;
	BigInteger DSA_parameter[]=new BigInteger[6];
	BigInteger DSA_private_key;
	BigInteger ECDSA_parameter[]=new BigInteger[6];
	BigInteger ECDSA_private_key;
	BigInteger r;
	BigInteger ECDSA_DH_singed_hash;
	//-----------------------------GCD-----------------------------------
	// Calculus of GCD(a,b):  https://www.dcode.fr/gcd
	boolean gcd(BigInteger a,BigInteger b) {
		BigInteger temp;
		while (!b.equals(BigInteger.ZERO)) {
			temp=b;
			b=a.mod(b);
			a=temp;
		}
		if(a.equals(BigInteger.ONE)) 
			return true;
		return false;
	}
	//-----------------------------Inverse--------------------------------
	//https://www.dcode.fr/modular-inverse
	public static BigInteger inverse(BigInteger modulus, BigInteger a, BigInteger temp, BigInteger reverse_of_a) {
	    if (!a.equals(BigInteger.ONE))
	        reverse_of_a = inverse(a, modulus.mod(a),reverse_of_a,temp.subtract(modulus.divide(a).multiply(reverse_of_a)));
	    return reverse_of_a;
	    }
	/*
	BigInteger inverse(BigInteger modulus,BigInteger b, BigInteger temp, BigInteger reverse_of_a) {
		BigInteger b1 = new BigInteger("0");
		BigInteger b2 = new BigInteger("1");
		BigInteger temp1;	
		BigInteger temp2 = modulus;
		while (!b.equals(BigInteger.ONE)) {
			temp1=b2;
			b2=b1.subtract(modulus.divide(b).multiply(b2));
			b1=temp1;
			temp1=b;
			b=modulus.mod(b);
			modulus=temp1;
		}
		if(b2.compareTo(BigInteger.ZERO)<0) {
			return b2.add(temp2);
		}
		return b2;	
	}*/
	//-------------------------logarithm base 2---------------------------
	 int logarithm(BigInteger a) {
		 int i=0;
		 while (!a.equals(BigInteger.ONE)) {
			a=a.divide(BigInteger.valueOf(2));
			i++;
		}
		return i;
	}
	//---------------------------efficient_pow----------------------------
	 //https://www.dcode.fr/modular-exponentiation
	 BigInteger efficient_pow(BigInteger message,BigInteger key,BigInteger n) {
		int log=logarithm(key) ;
		BigInteger pointer[]=new BigInteger[log+1];
		BigInteger array[] = new BigInteger[log+1];
		BigInteger f=new BigInteger("1");
		int i=0;
		pointer[i]=f;
		array[i]=message;
		do {
			i++;
			f=f.add(f);
			message=message.multiply(message).mod(n);
			array[i]=message;
			pointer[i]=f;		
		}while (log>i);
		while (true) {
			key=key.subtract(pointer[log]);
			if(key.equals(BigInteger.ZERO)) {
				break;
			}
			log=logarithm(key);
			message=message.multiply(array[log]).mod(n);
		}
		return message;
	}	
	//-------------------------------SHA1--------------------------------
	 BigInteger sha1(BigInteger[] eCDH_public) throws NoSuchAlgorithmException {
		 String input="";
		 for (int i = 0; i < eCDH_public.length; i++) {
			input=input+eCDH_public[i];
		 }
		 MessageDigest mDigest = MessageDigest.getInstance("SHA1");
	     byte[] result = mDigest.digest(input.getBytes());
	     StringBuffer sb = new StringBuffer();
	     for (int i = 0; i < result.length; i++) {
	         sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
	     }
	     BigInteger sha_decimal = null;
	     sha_decimal=Hex_to_Decimal(sb.toString());
	     return sha_decimal;
	 }
	//---------------------------Hex_to_Decimal--------------------------
	 BigInteger Hex_to_Decimal(String hex){
		 String digits = "0123456789ABCDEF";
	     hex = hex.toUpperCase();
         BigInteger val=new BigInteger("0");
         for (int i = 0; i < hex.length(); i++) {
             char c = hex.charAt(i);
             int d = digits.indexOf(c);
             val = val.multiply(BigInteger.valueOf(16)).add(BigInteger.valueOf(d));
	         }
         return val;
	}
		//-------------------------RSA_Key_Generation------------------------
	 void RSA_Key_Generation() {
		// User parameter
		int BIT_LENGTH = 1024;
		// Generate random primes
		SecureRandom rand = new SecureRandom();
		SecureRandom rand1 = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(BIT_LENGTH, rand);
		BigInteger q = BigInteger.probablePrime(BIT_LENGTH, rand1);
		System.out.println("random prime:p");
		System.out.println(p);
		System.out.println("random prime:q");
		System.out.println(q);
		// Calculate products
		n = p.multiply(q);
		System.out.println("n=(p*q):");
		System.out.println(n);
		BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		System.out.println("phi(n):");
		System.out.println(phi_n);
		// Generate public Key
		do RSA_public_key = new BigInteger(phi_n.bitLength(), rand);
		while (RSA_public_key.compareTo(BigInteger.ONE) <= 0
		    || RSA_public_key.compareTo(phi_n) >= 0
		    || !gcd(RSA_public_key,phi_n));
    	System.out.println("RSA_Public_Key:");
    	System.out.println(RSA_public_key);
    	// Generate private Key
    	//https://www.dcode.fr/modular-inverse
    	RSA_private_key=inverse(phi_n, RSA_public_key, BigInteger.valueOf(0), BigInteger.valueOf(1)).mod(phi_n); // inverse(...).mod(phi_n); in the cases that returned value is negative
    	System.out.println("RSA_Private Key:");
    	System.out.println(RSA_private_key);
	}
	 
	//--------------------------------Sign--------------------------------------
	 BigInteger sign(BigInteger ECDH_hash, BigInteger key,BigInteger RSA_n) {
		 System.out.println("hash :"+ ECDH_hash);
		 BigInteger enc=efficient_pow(ECDH_hash, /*RSA_private_key*/ key ,RSA_n);
		 System.out.println("sing :"+enc);
		 return enc;
	 }
	//-------------------------encrypt & Verification---------------------------
	 boolean encrypt_Verification(BigInteger ECDH_signed_hash,BigInteger[] ECDHE_public,BigInteger key,BigInteger RSA_n) {
		//Message decryption
    	 BigInteger dec=efficient_pow(ECDH_signed_hash, key, RSA_n);
    	 System.out.println("dec :"+dec);
    	 try {
    		 BigInteger hash = sha1(ECDHE_public);
    		 if (dec.equals(hash)) 
    			 return true;
    		 else
    			 return false;
 		} catch (NoSuchAlgorithmException e) {
 			// TODO Auto-generated catch block
 			e.printStackTrace();
 		}
    	 System.out.println("-------------------");
		 return false;
	 }
	 //------------------------------addition----------------------------------
	 //http://www.christelbach.com/ECCalculator.aspx
	 void addition(BigInteger x1, BigInteger y1,BigInteger x2,BigInteger y2, ECDHE_RSA ab) {
		 BigInteger s;
		 s=y2.subtract(y1).multiply(inverse(DH_public_parameter[2], x2.subtract(x1).mod(DH_public_parameter[2]), BigInteger.valueOf(0), BigInteger.valueOf(1))).mod(DH_public_parameter[2]);
		 ab.DH_public_parameter[0]=s.multiply(s).subtract(x1).subtract(x2).mod(DH_public_parameter[2]);
		 ab.DH_public_parameter[1]=s.multiply(x1.subtract(ab.DH_public_parameter[0])).subtract(y1).mod(DH_public_parameter[2]);
	 }
	 //------------------------------doubling----------------------------------
	 //http://www.christelbach.com/ECCalculator.aspx
	 void doubling(BigInteger x, BigInteger y, ECDHE_RSA ab) {
		 BigInteger s;
		 s=x.multiply(x).multiply(BigInteger.valueOf(3)).add(BigInteger.valueOf(-3)).multiply(inverse(DH_public_parameter[2], y.multiply(BigInteger.valueOf(2)).mod(DH_public_parameter[2]), BigInteger.valueOf(0), BigInteger.valueOf(1))).mod(DH_public_parameter[2]);
		 ab.DH_public_parameter[0]=s.multiply(s).subtract(x).subtract(x).mod(DH_public_parameter[2]);
		 ab.DH_public_parameter[1]=s.multiply(x.subtract(ab.DH_public_parameter[0])).subtract(y).mod(DH_public_parameter[2]);
	 }
	//----------------------------double and add----------------------------------
	 void double_and_add(BigInteger d,ECDHE_RSA ab) {
		 //https://www.rapidtables.com/convert/number/decimal-to-binary.html
		 BigInteger a;
	     String s = "";
	     while(d.compareTo(BigInteger.ZERO)>0){
	    	 a = d.mod(BigInteger.valueOf(2));
	         s = s + "" + a;
	         d = d.divide(BigInteger.valueOf(2));
	     }
	     char[] str=s.toCharArray();
	     int str_length=0;
	     str_length=(str.length)-2;
	     
	     //double and add Algorithm
	     while (str_length>=0) {
	    	 if(str[str_length]=='1') {
	    		 doubling(ab.DH_public_parameter[0], ab.DH_public_parameter[1], ab);
	    		 addition(x, y, ab.DH_public_parameter[0], ab.DH_public_parameter[1], ab);
	    	 }else 
	    		 doubling(ab.DH_public_parameter[0], ab.DH_public_parameter[1], ab);
			str_length--;
		}
	 }
	//----------------------------DH key generation----------------------------------
	 void DH_key_generation(ECDHE_RSA ab) {
		 System.out.println(ab.ECDSA_parameter[0]);
		 ab.DH_public_parameter[0]=x;
		 ab.DH_public_parameter[1]=y;
		 ab.DH_public_parameter[2]=p;
		 SecureRandom rand = new SecureRandom();
		 do ab.DH_private_key= new BigInteger(order.bitLength(), rand);
		 while (ab.DH_private_key.compareTo(BigInteger.ONE) <= 0
			|| ab.DH_private_key.compareTo(order) >= 0);
		 System.out.println("DH_private_key : "+'\n'+ab.DH_private_key);
		 double_and_add(ab.DH_private_key,ab);
		 System.out.println("DH_public_key_x : "+'\n'+ab.DH_public_parameter[0]);
		 System.out.println("DH_public_key_y : "+'\n'+ab.DH_public_parameter[1]);
		 
		 //---------------------------
		 
		 
	 }
	 //-------------------------------share key---------------------------------------
	 void share_key(ECDHE_RSA ab, BigInteger private_key) {
		 x=ab.DH_public_parameter[0];
		 y=ab.DH_public_parameter[1];
		 double_and_add(private_key, ab);
		 System.out.println("Sx : "+ab.DH_public_parameter[0]);
		 System.out.println("Sy : "+ab.DH_public_parameter[1]);
	 }
	//----------------------------DSA key generation----------------------------------
	 void DSA_key_generation(ECDHE_RSA ab) throws NoSuchAlgorithmException {
		 Random random = new Random();
		 BigInteger m;
		 BigInteger mr;
		 BigInteger p = new BigInteger("1");
 	     BigInteger q = BigInteger.probablePrime(160, random);
 	     BigInteger g;
 	     BigInteger h = new BigInteger("2");

 	    	 for(int i=1; i<=4096;i++) {
 	    		 m = new BigInteger(1024, random);
 	    		 mr=m.mod(BigInteger.TWO.multiply(q));
 	    		 p=m.subtract(mr);
 	    		 if(p.add(BigInteger.ONE).isProbablePrime(1)) {
 	    			 break;
 	    		 }
 	    	 }
 	    //}
 	    p=p.add(BigInteger.ONE)	 ;
 	    g=h.modPow(p.subtract(BigInteger.ONE).divide(q),p );
 	    System.out.println("p:"+p);
 		System.out.println("q:"+q);
 		System.out.println("g:"+g);
	        BigInteger d = new BigInteger(q.bitLength()-4, random);
	        System.out.println("d:"+d);
	        BigInteger e=efficient_pow(g, d, p);
	        System.out.println("e:"+e); 
	        DSA_parameter[0]=p;
	        DSA_parameter[1]=q;
	        DSA_parameter[2]=g;
	        DSA_parameter[3]=e;
	        DSA_parameter[4]=d;
	        DSA_parameter[5]=null;
	 }

	 BigInteger DSA_sign(BigInteger ECDH_hash, BigInteger[] DSA_parameter) {
		 Random random = new Random();
		 BigInteger ke;
		 do ke = new BigInteger(DSA_parameter[1].bitLength()-4, random);
			while (!gcd(ke,DSA_parameter[1]));
		 BigInteger r = efficient_pow(DSA_parameter[2], ke, DSA_parameter[0]).mod(DSA_parameter[1]);
		 DSA_parameter[5]=r;
		 BigInteger enc=(ECDH_hash.add(DSA_parameter[4].multiply(r))).multiply(inverse(DSA_parameter[1], ke, BigInteger.valueOf(0), BigInteger.valueOf(1))).mod(DSA_parameter[1]);
		 System.out.println("sing :"+enc);
		 return enc;
	 }
	//-------------------------------Verification---------------------------
	 boolean DSA_Verification(BigInteger ECDH_signed_hash,BigInteger[] ECDHE_public,BigInteger[]  DSA_parameter) throws NoSuchAlgorithmException {
		 BigInteger w=inverse(DSA_parameter[1], ECDH_signed_hash, BigInteger.valueOf(0), BigInteger.valueOf(1)).mod(DSA_parameter[1]);
		 BigInteger u1=w.multiply(sha1(ECDHE_public)).mod(DSA_parameter[1]);
		 BigInteger u2=w.multiply(DSA_parameter[5]).mod(DSA_parameter[1]);
		 BigInteger v=efficient_pow(DSA_parameter[2], u1,DSA_parameter[0]).multiply(efficient_pow(DSA_parameter[3],u2,DSA_parameter[0])).mod(DSA_parameter[0]).mod(DSA_parameter[1]);
		 System.out.println("dec :"+v.mod(DSA_parameter[1]));
		 if (v.mod(DSA_parameter[1]).equals(DSA_parameter[5]))
			 return true;
		 else
			 return false;

	 }
	//------------------------------addition----------------------------------
		 //http://www.christelbach.com/ECCalculator.aspx
		 void ECDSA_addition(BigInteger x1, BigInteger y1,BigInteger x2,BigInteger y2, ECDHE_RSA ab) {
			 BigInteger s;
			 s=(y2.subtract(y1)).multiply(inverse(ab.ECDSA_parameter[0], x2.subtract(x1).mod(ab.ECDSA_parameter[0]), BigInteger.valueOf(0), BigInteger.valueOf(1))).mod(ab.ECDSA_parameter[0]);
			 ab.ECDSA_parameter[4]=s.multiply(s).subtract(x1).subtract(x2).mod(ab.ECDSA_parameter[0]);
			 ab.ECDSA_parameter[5]=s.multiply(x1.subtract(ab.ECDSA_parameter[4])).subtract(y1).mod(ab.ECDSA_parameter[0]);
		 }
		 //------------------------------doubling----------------------------------
		 //http://www.christelbach.com/ECCalculator.aspx
		 void ECDSA_doubling(BigInteger x, BigInteger y, ECDHE_RSA ab) {
			 BigInteger s;
			 s=x.multiply(x).multiply(BigInteger.valueOf(3)).add(BigInteger.valueOf(-3)).multiply(inverse(ab.ECDSA_parameter[0], y.multiply(BigInteger.valueOf(2)).mod(ab.ECDSA_parameter[0]), BigInteger.valueOf(0), BigInteger.valueOf(1))).mod(ab.ECDSA_parameter[0]);
			 ab.ECDSA_parameter[4]=s.multiply(s).subtract(x).subtract(x).mod(ab.ECDSA_parameter[0]);
			 ab.ECDSA_parameter[5]=s.multiply(x.subtract(ab.ECDSA_parameter[4])).subtract(y).mod(ab.ECDSA_parameter[0]);
		 }
	 
	 void ECDSA_double_and_add(BigInteger d,ECDHE_RSA ab) {
		 //https://www.rapidtables.com/convert/number/decimal-to-binary.html
		 BigInteger a;
	     String s = "";
	     while(d.compareTo(BigInteger.ZERO)>0){
	    	 a = d.mod(BigInteger.valueOf(2));
	         s = s + "" + a;
	         d = d.divide(BigInteger.valueOf(2));
	     }
	     char[] str=s.toCharArray();
	     int str_length=0;
	     str_length=(str.length)-2;
	     
	     //double and add Algorithm
	     while (str_length>=0) {
	    	 if(str[str_length]=='1') {
	    		 ECDSA_doubling(ab.ECDSA_parameter[4], ab.ECDSA_parameter[5], ab);
	    		 ECDSA_addition(ab.x, ab.y, ab.ECDSA_parameter[4], ab.ECDSA_parameter[5], ab);
	    	 }else 
	    		 ECDSA_doubling(ab.ECDSA_parameter[4], ab.ECDSA_parameter[5], ab);
			str_length--;
		}
	 }
	 void ECDSA_key_generation(ECDHE_RSA ab) {
		 ab.ECDSA_parameter[0]=ab.p;
		 ab.ECDSA_parameter[1]=ab.order;
		 ab.ECDSA_parameter[2]=ab.x;
		 ab.ECDSA_parameter[3]=ab.y;
		 ab.ECDSA_parameter[4]=ab.x;
		 ab.ECDSA_parameter[5]=ab.y;
		 
		 SecureRandom rand = new SecureRandom();
		 do ab.ECDSA_private_key= new BigInteger(order.bitLength(), rand);
		 while (ab.ECDSA_private_key.compareTo(BigInteger.ONE) <= 0
			|| ab.ECDSA_private_key.compareTo(order) >= 0);
		 //ab.ECDSA_private_key=BigInteger.valueOf(7); 
		 System.out.println("ECDSA_private_key : "+'\n'+ab.ECDSA_private_key);
		 ECDSA_double_and_add(ab.ECDSA_private_key,ab);
		 System.out.println("ECDSA_public_key_x : "+'\n'+ab.ECDSA_parameter[4]);
		 System.out.println("ECDSA_public_key_y : "+'\n'+ab.ECDSA_parameter[5]);
		 
	 }
	 BigInteger ECDSA_sign(BigInteger ECDH_hash, /*BigInteger[] ECDSA_parameter,*/ECDHE_RSA ab) {
		 Random random = new Random();
		 BigInteger ke;
		 do ke = new BigInteger(order.bitLength()-4, random);
			while (!gcd(ke,order));
		 //ke=BigInteger.valueOf(10);
		 BigInteger xx=ab.ECDSA_parameter[4];
		 BigInteger yy=ab.ECDSA_parameter[5];
		 ab.ECDSA_parameter[4]=ab.ECDSA_parameter[2];
		 ab.ECDSA_parameter[5]=ab.ECDSA_parameter[3];
		 ECDSA_double_and_add(ke,ab);
		 r = ab.ECDSA_parameter[4];
		 
		 ab.ECDSA_parameter[4]=xx;
		 ab.ECDSA_parameter[5]=yy;

		 BigInteger enc=(ECDH_hash.add(ab.ECDSA_private_key.multiply(r))).multiply(inverse(ab.ECDSA_parameter[1], ke, BigInteger.valueOf(0), BigInteger.valueOf(1))).mod(ab.ECDSA_parameter[1]);
		 System.out.println("sing :"+enc);
		 return enc;
	 }
	//-------------------------------Verification---------------------------
	
	 boolean ECDSA_Verification(BigInteger ECDH_signed_hash,BigInteger[] ECDHE_public/*,BigInteger[]  ECDSA_parameter*/,ECDHE_RSA ab) throws NoSuchAlgorithmException {
		 BigInteger w=inverse(ab.ECDSA_parameter[1], /*BigInteger.valueOf(17)*/ ECDH_signed_hash, BigInteger.valueOf(0), BigInteger.valueOf(1)).mod(ab.ECDSA_parameter[1]);
		 BigInteger u1=w.multiply(sha1(/*BigInteger.valueOf(26)*/ECDHE_public)).mod(ab.ECDSA_parameter[1]);
		 BigInteger u2=w.multiply(ab.r).mod(ab.ECDSA_parameter[1]);
		 ab.ECDSA_parameter[2]=ab.ECDSA_parameter[4];
		 ab.ECDSA_parameter[3]=ab.ECDSA_parameter[5];
		 ab.ECDSA_parameter[4]=ab.x;
		 ab.ECDSA_parameter[5]=ab.y;
		
		 ECDSA_double_and_add(u1,ab);
		 BigInteger xx=ab.ECDSA_parameter[4];
		 BigInteger yy=ab.ECDSA_parameter[5];
		 
		 ab.ECDSA_parameter[4]=ab.ECDSA_parameter[2];
		 ab.ECDSA_parameter[5]=ab.ECDSA_parameter[3];
		 
		 ab.ECDSA_parameter[2]=ab.x;
		 ab.ECDSA_parameter[3]=ab.y;
		 ab.x=ab.ECDSA_parameter[4];
		 ab.y=ab.ECDSA_parameter[5];

		 ECDSA_double_and_add(u2,ab);
		 
		 ECDSA_addition(xx, yy,ab.ECDSA_parameter[4],ab.ECDSA_parameter[5], ab);
		 
		 if (ab.ECDSA_parameter[4].mod(ab.ECDSA_parameter[1]).equals(ab.r)) 
			 return true;
		 else 
			 return false;

	 }
}
