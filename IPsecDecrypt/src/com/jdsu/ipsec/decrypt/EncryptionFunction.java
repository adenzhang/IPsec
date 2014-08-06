package com.jdsu.ipsec.decrypt;

public interface EncryptionFunction {
    byte[] apply(byte[] cipher);
}
