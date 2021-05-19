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

	/***
	 * Transform an ByteArray to an 256 Bit SecretKey for AES
	 * @param byteArray
	 * @return SecretKey
	 */
	public static SecretKey byteArrayToSecretKey(byte[] byteArray) {
		MessageDigest sha256 = null;
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		byte[] tempKey = Arrays.copyOf(sha256.digest(byteArray), AES_KEY_SIZE / Byte.SIZE);
		SecretKey secretKey = new SecretKeySpec(tempKey, "AES");

		return secretKey;
	}

	/***
	 * Execute Diffie Hellman key exchange on connection. Client's side.
	 * @param connection
	 * @return generated SecretKey
	 */
	public static SecretKey executeClientSide(Connection connection) {


		// Client creates her own DH key pair with 2048-bit key size
		KeyAgreement clientKeyAgree = null;
		try {
			KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
			clientKpairGen.initialize(2048);
			KeyPair clientKpair = clientKpairGen.generateKeyPair();

			// Client creates and initializes her DH KeyAgreement object
			clientKeyAgree = KeyAgreement.getInstance("DH");
			clientKeyAgree.init(clientKpair.getPrivate());

			// Client encodes public key and sends it to server
			byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
			connection.send(clientPubKeyEnc);

		}catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}

		// receive response from server
		byte[] serverPubKeyEnc = connection.receive();
		try {
			KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
			PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
			clientKeyAgree.doPhase(serverPubKey, true);
		}catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e){
			e.printStackTrace();
		}

		// create the secret Key
		byte[] clientSharedSecret = clientKeyAgree.generateSecret();
		SecretKey secretKey = byteArrayToSecretKey(clientSharedSecret);

		System.out.println("Keys exchanged!");
		return secretKey;
	}

	/***
	 * Execute Diffie Hellman key exchange on connection. Server's side.
	 * @param connection
	 * @return generated SecretKey
	 */
	public static SecretKey executeServerSide(Connection connection) {

		// receive public key from client
		byte[] clientPubKeyEnc = connection.receive();
		PublicKey clientPubKey = null;

		// instantiate the server DH public key from encoded client key
		try {
			KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);
			clientPubKey = serverKeyFac.generatePublic(x509KeySpec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}

		DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey)clientPubKey).getParams();

		// Server creates his own DH key pair
		KeyPair serverKpair = null;
		KeyAgreement serverKeyAgree = null;
		try {
			KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
			serverKpairGen.initialize(dhParamFromClientPubKey);
			serverKpair = serverKpairGen.generateKeyPair();
			serverKeyAgree = KeyAgreement.getInstance("DH");
			serverKeyAgree.init(serverKpair.getPrivate());
		}catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e){
			e.printStackTrace();
		}
		// server encodes his public key and sends it to client.
		byte[] bobPubKeyEnc = serverKpair.getPublic().getEncoded();
		connection.send(bobPubKeyEnc);


		try {
			serverKeyAgree.doPhase(clientPubKey, true);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		// create secret key
		byte[] serverSharedSecret = serverKeyAgree.generateSecret();
		SecretKey secretKey = byteArrayToSecretKey(serverSharedSecret);

		System.out.println("Keys exchanged!");
		return secretKey;
	}
}
