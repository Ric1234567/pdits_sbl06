package de.ur.pdits.cryptchat.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class Encryption {

	private Cipher cipherEnc;
	private Cipher cipherDec;

	public Encryption(SecretKey symKey) {
		// TODO: Init ciphers

	}

	/**
	 * @param plaintext
	 *            The plaintext to be encrypted
	 * @return The plaintext encrypted with the provided symKey by the cipher
	 *         defined inside the constructor
	 */
	public byte[] encryptSymmetrically(byte[] plaintext) {
		// TODO: Execute encryption

		return null;
	}

	/**
	 * @param ciphertext
	 *            The ciphertext to be decrypted
	 * @return The ciphertext decrypted with the provided symKey by the cipher
	 *         defined inside the constructor
	 */
	public byte[] decryptSymmetrically(byte[] ciphertext) {
		// TODO: Execute decryption

		return null;
	}

}
