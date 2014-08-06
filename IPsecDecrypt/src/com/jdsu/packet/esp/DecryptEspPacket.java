package com.jdsu.packet.esp;

import java.util.Arrays;

import com.jdsu.ipsec.decrypt.AuthentAlgorithm;
import com.jdsu.ipsec.decrypt.EncryptionAlgorithm;
import com.jdsu.packet.Fn;

public class DecryptEspPacket {
	EncryptionAlgorithm decryptAlgo;
	AuthentAlgorithm authAlgo;
	
	public byte[] packet;
	public int    posIP;
	public int    posIpPayload;
	public int    lenIpPayload;
	
	public final int    authResultSize;
	public final int    blockSize;
	
	public static final int ESP_HEADER_SIZE = 8;

	public DecryptEspPacket(String encKey, String authKey, EncryptionAlgorithm.Algo eDecAlgo, AuthentAlgorithm.Algo eAuthAlgo) {
		decryptAlgo = EncryptionAlgorithm.getInstance(eDecAlgo);
		authAlgo = AuthentAlgorithm.getInstance(eAuthAlgo);
		decryptAlgo.setEncryptionKey(Fn.readHex(encKey));
		authAlgo.setAuthentKey(Fn.readHex(authKey));

		authResultSize = authAlgo.resultSize;
		blockSize = decryptAlgo.blockSize;
}
	public DecryptEspPacket(EncryptionAlgorithm algo, AuthentAlgorithm algoAuth) {
		decryptAlgo = algo;
		authAlgo = algoAuth;
		authResultSize = authAlgo.resultSize;
		blockSize = decryptAlgo.blockSize;
	}
	void setPacket(byte[] packt) {
		packet = packt;
		posIP = Fn.locateIp(packet);
		int[] payload = Fn.locateIpPayload(packet, posIP);
		posIpPayload = payload[0];
		lenIpPayload = payload[1];
	}
	void setPacket(byte[] packt, int aPosIP) {
		packet = packt;
		posIP = aPosIP;
		int[] payload = Fn.locateIpPayload(packet, posIP);
		posIpPayload = payload[0];
		lenIpPayload = payload[1];
	}
	public byte[] decrypt(byte[] packt) {
		setPacket(packt);
		
		int espPayloadPos = posIpPayload + ESP_HEADER_SIZE;
		int espEncryptSize = lenIpPayload - ESP_HEADER_SIZE - authResultSize;
		
		byte[] iv = Arrays.copyOfRange(packet, espPayloadPos, espPayloadPos+blockSize);
//		System.out.println("-- IV:" + Integer.toString(iv.length));
//		System.out.println(Fn.printHex(iv));
		byte[] deciphered = decryptAlgo.decrypt(iv,  packet, espPayloadPos+blockSize, espEncryptSize-blockSize);

		return deciphered;
	}

	public byte[] removePadding(byte[] decrypted) {
		int padLen = decrypted[decrypted.length-2];
		
		return Arrays.copyOfRange(decrypted, 0, decrypted.length - (padLen+2));
	}
}
