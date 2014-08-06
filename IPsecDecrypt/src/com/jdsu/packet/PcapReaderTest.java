package com.jdsu.packet;

import java.util.Arrays;

import com.jdsu.ipsec.decrypt.AuthentAlgorithm;
import com.jdsu.ipsec.decrypt.EncryptionAlgorithm;
import com.jdsu.packet.esp.DecryptEspPacket;

public class PcapReaderTest {

	public static void main(String[] args) {

		test_readPcap_DecryptESP();
	}
	static void test_readPcap_DecryptESP() {
		
		String fn = "pcap/CapturedInSeatle/encrypted.pcap";
		String hexKey = "0xca05072fd0e3a72de4e9d5b2248eee98";//"0xca05072f d0e3a72d e4e9d5b2 248eee98";
		EncryptionAlgorithm.Algo eAlgo = EncryptionAlgorithm.Algo.AES_CBC;
		AuthentAlgorithm.Algo eAuthAlgo = AuthentAlgorithm.Algo.HMAC_SHA1_96;

//		String fn = "pcap/VoLTE_Captures_TMobile_SA-NULL/data10.pcap"; 
//		String hexKey = "0xfc6eed74fc93199ec7e07c358c72d909";//"0xca05072f d0e3a72d e4e9d5b2 248eee98";
//		EncryptionAlgorithm.Algo eAlgo = EncryptionAlgorithm.Algo.NULL;
//		AuthentAlgorithm.Algo eAuthAlgo = AuthentAlgorithm.Algo.HMAC_SHA1_96;

		PcapReader pcap = new PcapReader();
		if( !pcap.open(fn) )
			return;
		TimeRecord tr =  new TimeRecord();
		for(int i=0; i< 5; ++i)  // skip
			pcap.read(tr);
		byte[] packet = pcap.read(tr);
//		System.out.println(Fn.printHex(packet));
		
		int posIp = Fn.locateIp(packet);
		int[] payloadInfo = Fn.locateIpPayload(packet, posIp);
		
//		System.out.println(String.format("-- raw ESP Packet: %d, %d",payloadInfo[0], payloadInfo[1]));
//		System.out.println(Fn.printHex(Arrays.copyOfRange(packet, payloadInfo[0], payloadInfo[0] + payloadInfo[1])));
		
		//------------- test decryption
		
		DecryptEspPacket decryptEsp = new DecryptEspPacket(hexKey, "", eAlgo, eAuthAlgo);
		byte[] deciphered = decryptEsp.decrypt(packet);
		
		System.out.println("-- Decrypted ESP Payload:" + Integer.toString(deciphered.length));
		System.out.println(Fn.printHex(deciphered));
//		System.out.println("-- Decrypted ESP Packet without padding:");
//		System.out.println(Fn.printHex(decryptEsp.removePadding(deciphered)));
	}

}
