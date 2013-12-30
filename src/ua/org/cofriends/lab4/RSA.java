package ua.org.cofriends.lab4;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private final static BigInteger one = new BigInteger("1");
	private final static SecureRandom random = new SecureRandom();

	private BigInteger privateKey;
	private BigInteger publicKey;
	private BigInteger modulus;

	// generate an N-bit (roughly) public and private key
	RSA(int N) {
		BigInteger p = new BigInteger("239"); // BigInteger.probablePrime(N / 2, random);
		BigInteger q = new BigInteger("379"); // BigInteger.probablePrime(N / 2, random);
		BigInteger phi = (p.subtract(one)).multiply(q.subtract(one));

		modulus = p.multiply(q);
		publicKey = new BigInteger("17993"); // common value in practice = 2^16
												// + 1
		privateKey = publicKey.modInverse(phi);
	}
	
	private BigInteger getPublicKey() {
		return publicKey;
	}
	
	private BigInteger getModulos() {
		return modulus;
	}

	BigInteger encrypt(BigInteger message) {
		return message.modPow(publicKey, modulus);
	}

	BigInteger decrypt(BigInteger encrypted) {
		return encrypted.modPow(privateKey, modulus);
	}

	public String toString() {
		String s = "";
		s += "public  = " + publicKey + "\n";
		s += "private = " + privateKey + "\n";
		s += "modulus = " + modulus;
		return s;
	}

	public static void main(String[] args) {
		int N = 5;
		RSA key = new RSA(N);
		System.out.println(key);

		// create message by converting string to integer
		String s = "P";
		byte[] bytes = s.getBytes();
		BigInteger message = new BigInteger(bytes);

		BigInteger encrypt = key.encrypt(message);
		BigInteger decrypt = key.decrypt(encrypt);
		System.out.println("message   = " + s);
		System.out.println("encrpyted = " + new String(encrypt.toByteArray()));
		System.out.println("decrypted = " + new String(decrypt.toByteArray()));
		
		WienerAttack wiener = new WienerAttack();
		BigInteger privateKey = wiener.attack(key.getPublicKey(), key.getModulos()); // Start to attack

		if (privateKey.equals(BigInteger.ONE.negate())) {
			System.out.println("This attack is unsuccessful because there are no continued fractions fulfilling the requirements of private key.");
		} else {
			System.out.println("Private key:" + privateKey.toString());
		}
	}
}