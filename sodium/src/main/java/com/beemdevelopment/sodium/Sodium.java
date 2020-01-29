package com.beemdevelopment.sodium;

import com.beemdevelopment.sodium.util.DirectMemory;

import java.nio.ByteBuffer;

public class Sodium {
    private Sodium() {

    }

    static {
        System.loadLibrary("sodium-jni");
    }

    public static boolean init() {
        return SodiumJNI.sodium_init() != -1;
    }

    public static int crypto_pwhash_scryptsalsa208sha256_ll(byte[] passwd, byte[] salt, long N, int r, int p, byte[] key) {
        int res;

        try (DirectMemory mem = new DirectMemory()) {
            ByteBuffer passwdBuf = mem.wrap(passwd);
            ByteBuffer saltBuf = mem.wrap(salt);
            ByteBuffer keyBuf = mem.allocate(key.length);

            res = SodiumJNI.crypto_pwhash_scryptsalsa208sha256_ll(passwdBuf, passwd.length, saltBuf, salt.length, N, r, p, keyBuf, key.length);
            checkRes(res);
            keyBuf.get(key);
        }

        return res;
    }

    private static int checkRes(int res) {
        if (res < 0) {
            throw new RuntimeException(String.format("Libsodium function returned: %d", res));
        }
        return res;
    }
}
