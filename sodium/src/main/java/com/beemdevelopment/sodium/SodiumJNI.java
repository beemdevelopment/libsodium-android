package com.beemdevelopment.sodium;

import java.nio.ByteBuffer;

public class SodiumJNI {
    public static native int sodium_init();
    public static native int crypto_pwhash_scryptsalsa208sha256_ll(ByteBuffer passwd, int passwdlen, ByteBuffer salt, int saltlen, long N, int r, int p, ByteBuffer buf, int buflen);
}
