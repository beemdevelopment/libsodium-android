package com.beemdevelopment.sodium;

import com.beemdevelopment.sodium.util.DirectMemory;

import java.nio.ByteBuffer;

public class Sodium {
    static {
        System.loadLibrary("sodium-jni");
    }

    public static final int SECRETSTREAM_XCHACHA20POLY1305_ABYTES
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_abytes();
    public static final int SECRETSTREAM_XCHACHA20POLY1305_HEADER_BYTES
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_headerbytes();
    public static final int SECRETSTREAM_XCHACHA20POLY1305_KEY_BYTES
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_keybytes();
    public static final int SECRETSTREAM_XCHACHA20POLY1305_MESSAGE_BYTES_MAX
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_messagebytes_max();
    public static final byte SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_tag_message();
    public static final byte SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_tag_push();
    public static final byte SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_tag_rekey();
    public static final byte SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_tag_final();
    public static final int SECRETSTREAM_XCHACHA20POLY1305_STATE_BYTES
            = SodiumJNI.crypto_secretstream_xchacha20poly1305_statebytes();

    private Sodium() {

    }

    public static int init() {
        return SodiumJNI.sodium_init();
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

    public static void crypto_secretstream_xchacha20poly1305_keygen(byte[] key) {
        try (DirectMemory mem = new DirectMemory()) {
            ByteBuffer keyBuf = mem.allocate(key.length);
            SodiumJNI.crypto_secretstream_xchacha20poly1305_keygen(keyBuf);
            keyBuf.get(key);
        }
    }

    private static int checkRes(int res) {
        if (res < 0) {
            throw new RuntimeException(String.format("Libsodium function returned: %d", res));
        }
        return res;
    }
}
