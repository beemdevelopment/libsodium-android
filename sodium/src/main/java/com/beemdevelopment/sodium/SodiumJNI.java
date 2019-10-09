package com.beemdevelopment.sodium;

import java.nio.ByteBuffer;
import java.nio.LongBuffer;

public class SodiumJNI {
    private SodiumJNI() {

    }

    public static native int sodium_init();

    public static native int crypto_pwhash_scryptsalsa208sha256_ll(ByteBuffer passwd, int passwdlen, ByteBuffer salt, int saltlen, long N, int r, int p, ByteBuffer buf, int buflen);

    public static native int crypto_secretstream_xchacha20poly1305_abytes();
    public static native int crypto_secretstream_xchacha20poly1305_headerbytes();
    public static native int crypto_secretstream_xchacha20poly1305_keybytes();
    public static native int crypto_secretstream_xchacha20poly1305_messagebytes_max();
    public static native byte crypto_secretstream_xchacha20poly1305_tag_message();
    public static native byte crypto_secretstream_xchacha20poly1305_tag_push();
    public static native byte crypto_secretstream_xchacha20poly1305_tag_rekey();
    public static native byte crypto_secretstream_xchacha20poly1305_tag_final();
    public static native int crypto_secretstream_xchacha20poly1305_statebytes();

    public static native void crypto_secretstream_xchacha20poly1305_keygen(ByteBuffer key);
    public static native int crypto_secretstream_xchacha20poly1305_init_push(ByteBuffer state, ByteBuffer header, ByteBuffer key);
    public static native int crypto_secretstream_xchacha20poly1305_push(ByteBuffer state, ByteBuffer c, LongBuffer clen_p, ByteBuffer m, int mlen, ByteBuffer ad, int adlen, byte tag);
    public static native int crypto_secretstream_xchacha20poly1305_init_pull(ByteBuffer state, ByteBuffer header, ByteBuffer key);
    public static native int crypto_secretstream_xchacha20poly1305_pull(ByteBuffer state, ByteBuffer m, LongBuffer mlen_p, ByteBuffer tag, ByteBuffer c, int clen, ByteBuffer ad, int adlen);
    public static native void crypto_secretstream_xchacha20poly1305_rekey(ByteBuffer state);
}
