package de.ur.pdits.cryptchat.security;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;



public class Encryption {

	private Cipher cipherEnc;
	private Cipher cipherDec;

	public Encryption(SecretKey symKey) {
		// set init vector
		byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		// init Cypher, using CBC Mode with PKCS5 Padding
		try {
			cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipherEnc.init(Cipher.ENCRYPT_MODE, symKey, ivspec);

			cipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipherDec.init(Cipher.DECRYPT_MODE, symKey, ivspec);

		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Encrypt given plaintext with AES
	 * @param plaintext
	 *            The plaintext to be encrypted
	 * @return The plaintext encrypted with the provided symKey by the cipher
	 *         defined inside the constructor
	 */
	public byte[] encryptSymmetrically(byte[] plaintext)  {
		byte[] cipherText = new byte[plaintext.length];

		try {
			cipherText = cipherEnc.doFinal(plaintext);

		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	/**
	 * Decrypt given ciphertext with AES
	 * @param ciphertext
	 *            The ciphertext to be decrypted
	 * @return The ciphertext decrypted with the provided symKey by the cipher
	 *         defined inside the constructor
	 */
	public byte[] decryptSymmetrically(byte[] ciphertext) {
		byte[] plainText = new byte[ciphertext.length];

		try {
			plainText = cipherDec.doFinal(ciphertext);

		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return plainText;
	}

}
