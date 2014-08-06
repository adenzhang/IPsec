package com.jdsu.ipsec.decrypt;

class EncryptNull extends EncryptionAlgorithm {
	public EncryptNull() {
		super("NULL", 0, 0);
	}

	@Override
	public byte[] decrypt(byte[] iv, byte[] cipher, int startPos, int len) {
		byte[] deciphered = new byte[len];
		System.arraycopy(cipher, startPos, deciphered, 0, len);
		return deciphered;
	}
	
	static public boolean detectNull(byte[] cipher, int startPos, int len) {
		// todo
		return false;
	}
}