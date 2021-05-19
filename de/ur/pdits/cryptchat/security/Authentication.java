package de.ur.pdits.cryptchat.security;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
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
			PrivateKey key = kf.generatePrivate(ks);
			return key;
		} catch (Exception e) {
			System.out.println("Failed to load private key from path " + keyFile.getAbsolutePath());
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] signChallenge(byte[] challenge, PrivateKey signKey) {
		// TODO: Sign the challenge with the provided private key

		return null;
	}

	public static boolean signatureValid(byte[] challenge, byte[] signature, X509Certificate cert) {
		// TODO: verify signature (test if decrypted response matches the
		// unencrypted challenge)

		return false;
	}

	/**
	 * 
	 * @param authKeyFile
	 *            File containing the own private key to sign server's
	 *            challenges with
	 * @param partnerAuthCertFile
	 *            File containing the server's certificate to validate his
	 *            signatures with
	 * @return True if authentication was successful, false else
	 */
	public static boolean executeClient(Connection connection, File authKeyFile, File partnerAuthCertFile) {
		// TODO: Verify server's authenticity

		// 0) load client's private key and server's cert

		// 1) Send client's challenge

		// 2) receive signed challenge

		// 3) receive server's challenge

		// 4) respond signed challenge

		// 5) return true if server's signature is valid
		return true;
	}

	/**
	 * 
	 * @param authKeyFile
	 *            File containing the own private key to sign client's
	 *            challenges with
	 * @param partnerAuthCertFile
	 *            File containing the client's certificate to validate his
	 *            signature with
	 * @return True if authentication was successful, false else
	 */
	public static boolean executeServer(Connection connection, File authKeyFile, File partnerAuthCertFile) {
		// TODO: Verify client's authenticity

		// 0) load server's private key and client's cert

		// 1) receive client's challenge

		// 2) respond signed challenge

		// 3) send server's challenge

		// 4) receive signed challenge

		// 5) return true if client's signature is valid
		return true;
	}

}
