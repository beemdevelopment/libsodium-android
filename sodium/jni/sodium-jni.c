#include <jni.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "sodium.h"
#include "sodium/crypto_pwhash_scryptsalsa208sha256.h"
#include "sodium/crypto_secretstream_xchacha20poly1305.h"

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_sodium_1init(JNIEnv* env, jclass class) {
    return sodium_init();
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1pwhash_1scryptsalsa208sha256_1ll(JNIEnv* env, jclass class,
                                                                                   jobject passwd, jsize passwdlen,
                                                                                   jobject salt, jsize saltlen,
                                                                                   jlong N, jint r, jint p,
                                                                                   jobject buf, jsize buflen) {
    jbyte *cpasswd = (jbyte *) (*env)->GetDirectBufferAddress(env, passwd);
    jbyte *csalt = (jbyte *) (*env)->GetDirectBufferAddress(env, salt);
    jbyte *cbuf = (jbyte *) (*env)->GetDirectBufferAddress(env, buf);

    return crypto_pwhash_scryptsalsa208sha256_ll((const uint8_t *) cpasswd, (size_t) passwdlen,
                                                 (const uint8_t *) csalt, (size_t) saltlen,
                                                 (uint64_t) N, (uint32_t) r, (uint32_t) p,
                                                 (uint8_t *) cbuf, (size_t) buflen);
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1abytes(JNIEnv* env, jclass class) {
    return (jsize) crypto_secretstream_xchacha20poly1305_abytes();
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1headerbytes(JNIEnv* env, jclass class) {
    return (jsize) crypto_secretstream_xchacha20poly1305_headerbytes();
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1keybytes(JNIEnv* env, jclass class) {
    return (jsize) crypto_secretstream_xchacha20poly1305_keybytes();
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1messagebytes_1max(JNIEnv* env, jclass class) {
    return (jsize) crypto_secretstream_xchacha20poly1305_messagebytes_max();
}

JNIEXPORT jbyte JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1tag_1message(JNIEnv* env, jclass class) {
    return crypto_secretstream_xchacha20poly1305_tag_message();
}

JNIEXPORT jbyte JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1tag_1push(JNIEnv* env, jclass class) {
    return crypto_secretstream_xchacha20poly1305_tag_push();
}

JNIEXPORT jbyte JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1tag_1rekey(JNIEnv* env, jclass class) {
    return crypto_secretstream_xchacha20poly1305_tag_rekey();
}

JNIEXPORT jbyte JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1tag_1final(JNIEnv* env, jclass class) {
    return crypto_secretstream_xchacha20poly1305_tag_final();
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1statebytes(JNIEnv* env, jclass class) {
    return (jsize) crypto_secretstream_xchacha20poly1305_statebytes();
}

JNIEXPORT void JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1keygen(JNIEnv* env, jclass class, jobject key) {
    jbyte *ckey = (jbyte *) (*env)->GetDirectBufferAddress(env, key);
    crypto_secretstream_xchacha20poly1305_keygen((unsigned char *) ckey);
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1init_1push(JNIEnv* env, jclass class, jobject state, jobject header, jobject key) {
    jbyte *cstate = (jbyte *) (*env)->GetDirectBufferAddress(env, state);
    jbyte *cheader = (jbyte *) (*env)->GetDirectBufferAddress(env, header);
    jbyte *ckey = (jbyte *) (*env)->GetDirectBufferAddress(env, key);

    return crypto_secretstream_xchacha20poly1305_init_push(
            (crypto_secretstream_xchacha20poly1305_state *) cstate,
            (unsigned char *) cheader,
            (const unsigned char *) ckey);
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1push(JNIEnv* env, jclass class, jobject state, jobject c, jobject clen_p, jobject m, jint mlen, jobject ad, jint adlen, jbyte tag) {
    jbyte *cstate = (jbyte *) (*env)->GetDirectBufferAddress(env, state);
    jbyte *cc = (jbyte *) (*env)->GetDirectBufferAddress(env, c);
    jbyte *cclen_p = (jbyte *) (*env)->GetDirectBufferAddress(env, clen_p);
    jbyte *cm = (jbyte *) (*env)->GetDirectBufferAddress(env, m);

    jbyte *cad = NULL;
    if (ad) {
        cad = (jbyte *) (*env)->GetDirectBufferAddress(env, ad);
    }

    return crypto_secretstream_xchacha20poly1305_push(
            (crypto_secretstream_xchacha20poly1305_state *) cstate,
            (unsigned char *) cc, (unsigned long long int *) cclen_p,
            (const unsigned char *) cm, (unsigned long long int) mlen,
            (const unsigned char *) cad, (unsigned long long int) adlen,
            (unsigned char) tag);
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1init_1pull(JNIEnv* env, jclass class, jobject state, jobject header, jobject key) {
    jbyte *cstate = (jbyte *) (*env)->GetDirectBufferAddress(env, state);
    jbyte *cheader = (jbyte *) (*env)->GetDirectBufferAddress(env, header);
    jbyte *ckey = (jbyte *) (*env)->GetDirectBufferAddress(env, key);

    return crypto_secretstream_xchacha20poly1305_init_pull(
            (crypto_secretstream_xchacha20poly1305_state *) cstate,
            (const unsigned char *) cheader,
            (const unsigned char *) ckey);
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1pull(JNIEnv* env, jclass class, jobject state, jobject m, jobject mlen_p, jobject tag, jobject c, jint clen, jobject ad, jint adlen) {
    jbyte *cstate = (jbyte *) (*env)->GetDirectBufferAddress(env, state);
    jbyte *cm = (jbyte *) (*env)->GetDirectBufferAddress(env, m);
    jbyte *cmlen_p = (jbyte *) (*env)->GetDirectBufferAddress(env, mlen_p);
    jbyte *ctag = (jbyte *) (*env)->GetDirectBufferAddress(env, tag);
    jbyte *cc = (jbyte *) (*env)->GetDirectBufferAddress(env, c);

    jbyte *cad = NULL;
    if (ad) {
        cad = (jbyte *) (*env)->GetDirectBufferAddress(env, ad);
    }

    return crypto_secretstream_xchacha20poly1305_pull(
            (crypto_secretstream_xchacha20poly1305_state *) cstate,
            (unsigned char *) cm, (unsigned long long int *) cmlen_p,
            (unsigned char *) ctag,
            (const unsigned char *) cc, (unsigned long long int) clen,
            (const unsigned char *) cad, (unsigned long long int) adlen);
}

JNIEXPORT void JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1secretstream_1xchacha20poly1305_1rekey(JNIEnv* env, jclass class, jobject state) {
    jbyte *cstate = (jbyte *) (*env)->GetDirectBufferAddress(env, state);
    crypto_secretstream_xchacha20poly1305_rekey((crypto_secretstream_xchacha20poly1305_state *) cstate);
}
