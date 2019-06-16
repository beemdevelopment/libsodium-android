package com.beemdevelopment.sodium;

public class SodiumJNI {
    public static native int sodium_init();
    public static native int crypto_pwhash_scryptsalsa208sha256_ll(byte[] passwd, int passwdlen, byte[] salt, int saltlen, long N, int r, int p, byte[] buf, int buflen);
}
