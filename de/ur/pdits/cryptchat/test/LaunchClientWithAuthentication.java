package de.ur.pdits.cryptchat.test;

import de.ur.pdits.cryptchat.Main;

public class LaunchClientWithAuthentication {

	public static void main(String[] args) {
		String[] params = { "-client", "localhost", "1337", "-key=C:\\Users\\Sascha\\Desktop\\x509\\user1.key",
				"-cert=C:\\Users\\Sascha\\Desktop\\x509\\user2.crt" };
		Main.main(params);
	}
}
