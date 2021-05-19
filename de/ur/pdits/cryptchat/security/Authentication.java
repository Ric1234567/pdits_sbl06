package de.ur.pdits.cryptchat.security;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import de.ur.pdits.cryptchat.network.Connection;


public class Authentication {

	public static X509Certificate loadCert(File certFile) {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			FileInputStream finStream;
			finStream = new FileInputStream(certFile);
			X509Certificate cert = (X509Certificate) cf.generateCertificate(finStream);
			finStream.close();
			return cert;
		} catch (Exception e) {
			System.out.println("Failed to load certificate from path " + certFile.getAbsolutePath());
			e.printStackTrace();
			return null;
		}
	}

	public static PrivateKey loadPrivateKey(File keyFile) {
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			KeySpec ks = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(keyFile.getAbsolutePath())));
			return kf.generatePrivate(ks);
		} catch (Exception e) {
			System.out.println("Failed to load private key from path " + keyFile.getAbsolutePath());
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Sign the challenge with the provided private key
	 * @param challenge
	 * @param signKey
	 * @return
	 */
	public static byte[] signChallenge(byte[] challenge, PrivateKey signKey) {

		try {
			Signature privateSignature = Signature.getInstance("SHA256withRSA");
			privateSignature.initSign(signKey);
			privateSignature.update(challenge);
			return privateSignature.sign();
		} catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Verify signature (test if decrypted response matches the unencrypted challenge)
	 * @param challenge
	 * @param signature
	 * @param cert
	 * @return
	 */
	public static boolean signatureValid(byte[] challenge, byte[] signature, X509Certificate cert) {

		Signature publicSignature = null;
		try{
			publicSignature = Signature.getInstance("SHA256withRSA");
			publicSignature.initVerify(cert);
			publicSignature.update(challenge);
			return publicSignature.verify(signature);

		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * Verify server's authenticity
	 * @param authKeyFile
	 *            File containing the own private key to sign server's
	 *            challenges with
	 * @param partnerAuthCertFile
	 *            File containing the server's certificate to validate his
	 *            signatures with
	 * @return True if authentication was successful, false else
	 */
	public static boolean executeClient(Connection connection, File authKeyFile, File partnerAuthCertFile) {

		// 0) load client's private key and server's cert
		PrivateKey clientPrivateKey = loadPrivateKey(authKeyFile);
		X509Certificate serverCert = loadCert(partnerAuthCertFile);

		// 1) Send client's challenge
		byte[] clientChallenge = createRandomChallenge();
		connection.send(clientChallenge);

		// 2) receive signed challenge
		byte[] signedClientChallenge = connection.receive();

		// 3) receive server's challenge
		byte[] serverChallenge = connection.receive();

		// 4) respond signed challenge
		connection.send(signChallenge(serverChallenge, clientPrivateKey));

		// 5) return true if server's signature is valid
		if(signatureValid(clientChallenge, signedClientChallenge, serverCert)) {
			System.out.println("Client authentication valid!");
			return true;
		}
		System.out.println("Client authentication failed!");
		return false;
	}

	/**
	 * Verify client's authenticity
	 * @param authKeyFile
	 *            File containing the own private key to sign client's
	 *            challenges with
	 * @param partnerAuthCertFile
	 *            File containing the client's certificate to validate his
	 *            signature with
	 * @return True if authentication was successful, false else
	 */
	public static boolean executeServer(Connection connection, File authKeyFile, File partnerAuthCertFile) {

		// 0) load server's private key and client's cert
		PrivateKey serverPrivateKey = loadPrivateKey(authKeyFile);
		X509Certificate clientCert = loadCert(partnerAuthCertFile);

		// 1) receive client's challenge
		byte[] clientChallenge = connection.receive();

		// 2) respond signed challenge
		connection.send(signChallenge(clientChallenge, serverPrivateKey));

		// 3) send server's challenge
		byte[] serverChallenge = createRandomChallenge();
		connection.send(serverChallenge);

		// 4) receive signed challenge
		byte[] signedServerChallenge = connection.receive();

		// 5) return true if client's signature is valid
		if(signatureValid(serverChallenge, signedServerChallenge, clientCert)) {
			System.out.println("Server authentication valid!");
			return true;
		}
		System.out.println("Server authentication failed!");
		return false;
	}


	/**
	 * Create a random challenge with 128 Bytes
	 * @return
	 */
	private static byte[] createRandomChallenge(){
		byte[] bytes = new byte[128];
		try{
			SecureRandom.getInstanceStrong().nextBytes(bytes);
			return bytes;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
}
