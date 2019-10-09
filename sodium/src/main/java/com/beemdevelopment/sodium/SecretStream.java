package com.beemdevelopment.sodium;

import static com.beemdevelopment.sodium.Sodium.SECRETSTREAM_XCHACHA20POLY1305_KEY_BYTES;

public class SecretStream {
    // NOTE: DO NOT MODIFY
    public static final int CHUNK_SIZE = 4096;

    private SecretStream() {

    }

    public static byte[] generateKey() {
        byte[] key = new byte[SECRETSTREAM_XCHACHA20POLY1305_KEY_BYTES];
        Sodium.crypto_secretstream_xchacha20poly1305_keygen(key);
        return key;
    }
}
