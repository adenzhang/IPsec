package com.jdsu.packet;


public interface IPacketReader {

	boolean open(String url);
	
	byte[] read(TimeRecord tr);
	
	void close();
}
