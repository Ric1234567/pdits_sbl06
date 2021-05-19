package de.ur.pdits.cryptchat.security;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.ur.pdits.cryptchat.network.Connection;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


public class KeyExchange {

	private static final int AES_KEY_SIZE = 256;

	// Transform byte Array to 256 Bit Key
	public static SecretKey byteArrayToSecretKey(byte[] byteArray) {
		MessageDigest sha256 = null;
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		byte[] bkey = Arrays.copyOf(
				sha256.digest(byteArray), AES_KEY_SIZE / Byte.SIZE);

		SecretKey secretKey = new SecretKeySpec(bkey, "AES");
		System.out.println(secretKey);

		return secretKey;
	}

	public static SecretKey executeClientSide(Connection connection) {
		// TODO: Execute diffie hellman key exchange on connection

		/*
		 * Client creates her own DH key pair with 2048-bit key size
		 */
		KeyAgreement clientKeyAgree = null;
		try {
			System.out.println("CLIENT: Generate DH keypair ...");
			KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
			clientKpairGen.initialize(2048);
			KeyPair clientKpair = clientKpairGen.generateKeyPair();

			// Client creates and initializes her DH KeyAgreement object
			System.out.println("CLIENT: Initialization ...");
			clientKeyAgree = KeyAgreement.getInstance("DH");
			clientKeyAgree.init(clientKpair.getPrivate());

			// Client encodes public key, and sends it over to Server.
			byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
			connection.send(clientPubKeyEnc);

		}catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}


		/*
		 * Alice uses Bob's public key for the first (and only) phase
		 * of her version of the DH
		 * protocol.
		 * Before she can do so, she has to instantiate a DH public key
		 * from Bob's encoded key material.
		 */
		byte[] serverPubKeyEnc = connection.receive();
		try {
			KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
			PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
			System.out.println("CLIENT: Execute PHASE1 ...");
			clientKeyAgree.doPhase(serverPubKey, true);

		}catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e){
			e.printStackTrace();
		}


		byte[] clientSharedSecret = clientKeyAgree.generateSecret();
		SecretKey secretKey = byteArrayToSecretKey(clientSharedSecret);
		System.out.println(secretKey);

		return secretKey;
	}

	public static SecretKey executeServerSide(Connection connection) {
		// TODO: Execute diffie hellman key exchange on connection
		/* Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
		 * He instantiates a DH public key from the encoded key material.
         */
		byte[] clientPubKeyEnc = connection.receive();
		PublicKey clientPubKey = null;
		try {
			KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);
			 clientPubKey = bobKeyFac.generatePublic(x509KeySpec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}

		/*
		 * Bob gets the DH parameters associated with Alice's public key.
		 * He must use the same parameters when he generates his own key
		 * pair.
		 */
		DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey)clientPubKey).getParams();

		// Server creates his own DH key pair
		KeyPair serverKpair = null;
		KeyAgreement serverKeyAgree = null;
		try {
			System.out.println("SERVER: Generate DH keypair ...");
			KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
			serverKpairGen.initialize(dhParamFromClientPubKey);
			serverKpair = serverKpairGen.generateKeyPair();

			// Server creates and initializes his DH KeyAgreement object
			System.out.println("SERVER: Initialization ...");
			serverKeyAgree = KeyAgreement.getInstance("DH");
			serverKeyAgree.init(serverKpair.getPrivate());
		}catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e){
			e.printStackTrace();
		}
		// Server encodes his public key, and sends it over to Client.
		byte[] bobPubKeyEnc = serverKpair.getPublic().getEncoded();
		connection.send(bobPubKeyEnc);

		/*
		 * Bob uses Alice's public key for the first (and only) phase
		 * of his version of the DH
		 * protocol.
		 */
		try {
			System.out.println("BOB: Execute PHASE1 ...");
			serverKeyAgree.doPhase(clientPubKey, true);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		byte[] serverSharedSecret = serverKeyAgree.generateSecret();
		SecretKey secretKey = byteArrayToSecretKey(serverSharedSecret);
		System.out.println(secretKey);
		return secretKey;
	}

}
