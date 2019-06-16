package com.beemdevelopment.sodium;

public class Sodium {
    private Sodium() {

    }

    static {
        System.loadLibrary("sodium-jni");
    }

    public static int init() {
        return SodiumJNI.sodium_init();
    }

    public static int crypto_pwhash_scryptsalsa208sha256_ll(byte[] passwd, byte[] salt, long N, int r, int p, byte[] buf) {
        int res = SodiumJNI.crypto_pwhash_scryptsalsa208sha256_ll(passwd, passwd.length, salt, salt.length, N, r, p, buf, buf.length);
        return checkRes(res);
    }

    private static int checkRes(int res) {
        if (res < 0) {
            throw new RuntimeException(String.format("Libsodium function returned: %d", res));
        }
        return res;
    }
}
