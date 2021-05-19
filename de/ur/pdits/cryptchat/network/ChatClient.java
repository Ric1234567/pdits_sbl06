package de.ur.pdits.cryptchat.network;

import java.io.File;
import java.net.Socket;

import de.ur.pdits.cryptchat.security.Authentication;

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
		// TODO:
		// CryptChat 1.0: Initiate Cipher & hand it over to connection via
		// Connection.setEncryption()
		// CryptChat 2.0: Perform automatic KeyExchange using DiffieHellman to
		// ensure Perfect Forward Secrecy

	}
}
