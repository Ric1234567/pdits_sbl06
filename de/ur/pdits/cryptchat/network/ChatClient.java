package de.ur.pdits.cryptchat.network;

import java.io.File;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import de.ur.pdits.cryptchat.security.Authentication;
import de.ur.pdits.cryptchat.security.Encryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static de.ur.pdits.cryptchat.security.KeyExchange.executeClientSide;

public class ChatClient {

	public ChatClient(String serverHostname, int serverPort, File authKeyFile, File partnerAuthCertFile) {
		System.out.println("Connecting to server " + serverHostname + ":" + serverPort + " ...");

		Socket socket;
		try {
			socket = new Socket(serverHostname, serverPort);
		} catch (Exception e) {
			System.out.println("Failed to connect to " + serverHostname + ":" + serverPort + ".");
			return;
		}

		try {

			// 1/3) Establish network connection to send and receive byte arrays
			Connection connection = new Connection(socket);

			System.out.println("Connection established to " + connection.getSocket().getInetAddress() + ":"
					+ connection.getSocket().getPort());

			// 2/3) Execute security methods to ensure confidential
			// communication
			if (Authentication.executeClient(connection, authKeyFile, partnerAuthCertFile)) {
				initEncryption(connection);

				// 3/3) Switch into chat mode: Send any user inputs through the
				// connection, print any received messages on the console.
				System.out.println("Security Handshake finished, starting chat.");
				connection.startChat();

			} else {
				System.out.println("Failed to confirm server's authenticity. Closing connection.");
				connection.close();
			}

		} catch (Exception e) {
			System.out.println("Failed to establish secure connection:");
			e.printStackTrace();
		}
	}

	private void initEncryption(Connection connection) {
	/*
		// CryptChat 1.0: Initiate Cipher & hand it over to connection via
		String SECRET_KEY = "super-duper-geheimes-passwort";
		String SALT = "Etwas Salz in die Suppe!";

		SecretKey secretKey = null;

		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
	*/

		// CryptChat 2.0: Perform automatic KeyExchange using DiffieHellman to
		// ensure Perfect Forward Secrecy
		SecretKey secretKey = executeClientSide(connection);

		// set Encryption
		connection.setEncryption(new Encryption(secretKey));
	}
}
