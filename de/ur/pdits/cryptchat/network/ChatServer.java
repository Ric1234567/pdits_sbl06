package de.ur.pdits.cryptchat.network;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;

import de.ur.pdits.cryptchat.security.Authentication;

public class ChatServer {

	ServerSocket serverSocket;

	/**
	 * 
	 * @param port
	 *            The port to listen for client's conenction
	 * @param authKeyFile
	 *            Points to the authentication
	 * @param partnerAuthCertFile
	 */
	public ChatServer(int port, File authKeyFile, File partnerAuthCertFile) {

		try {
			serverSocket = new ServerSocket(port);
		} catch (IOException e) {
			System.out.println("Failed to listen on port " + port + ".");
			e.printStackTrace();
			System.exit(0);
		}

		System.out.println("Waiting for incoming connection...");

		try {

			// 1/3) Establish network connection to send and receive byte arrays
			Connection connection = new Connection(serverSocket.accept());

			System.out.println("Connection established from " + connection.getSocket().getInetAddress() + ":"
					+ connection.getSocket().getPort());

			// 2/3) Execute security methods to ensure confidential
			// communication
			if (Authentication.executeServer(connection, authKeyFile, partnerAuthCertFile)) {

				initEncryption(connection);

				// 3/3) Switch into chat mode: Send any user inputs through the
				// connection, print any received messages on the console.
				System.out.println("Security Handshake finished, starting chat.");

				connection.startChat();

			} else {
				System.out.println("Failed to confirm client's authenticity. Closing connection.");
				connection.close();
			}

		} catch (IOException e) {
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
