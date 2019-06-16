#include <jni.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "sodium.h"
#include "sodium/crypto_pwhash_scryptsalsa208sha256.h"

static bool get_jbytearray(JNIEnv* env, jbyteArray array, jbyte **copy) {
    jboolean isCopy;
    jbyte *buf = (*env)->GetByteArrayElements(env, array, &isCopy);
    if ((*env)->ExceptionCheck(env)) {
        return false;
    }

    *copy = buf;
    return true;
}

static bool release_jbytearray(JNIEnv* env, jbyteArray array, jbyte *copy) {
    (*env)->ReleaseByteArrayElements(env, array, copy, JNI_COMMIT);
    if ((*env)->ExceptionCheck(env)) {
        return false;
    }

    return true;
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_sodium_1init(JNIEnv* env, jclass class) {
    return sodium_init();
}

JNIEXPORT jint JNICALL
Java_com_beemdevelopment_sodium_SodiumJNI_crypto_1pwhash_1scryptsalsa208sha256_1ll(JNIEnv* env, jclass class,
                                                                                   jbyteArray passwd, jsize passwdlen,
                                                                                   jbyteArray salt, jsize saltlen,
                                                                                   jlong N, jint r, jint p,
                                                                                   jbyteArray buf, jsize buflen) {
    jbyte *cpasswd;
    if (!get_jbytearray(env, passwd, &cpasswd)) {
        return -1;
    }

    jbyte *csalt;
    if (!get_jbytearray(env, salt, &csalt)) {
        return -1;
    }

    jbyte *cbuf;
    if (!get_jbytearray(env, buf, &cbuf)) {
        return -1;
    }

    int res = crypto_pwhash_scryptsalsa208sha256_ll((const uint8_t *) cpasswd, (size_t) passwdlen,
                                                    (const uint8_t *) csalt, (size_t) saltlen,
                                                    (uint64_t) N, (uint32_t) r, (uint32_t) p,
                                                    (uint8_t *) cbuf, (size_t) buflen);

    if (!release_jbytearray(env, passwd, cpasswd)) {
        return -1;
    }
    if (!release_jbytearray(env, salt, csalt)) {
        return -1;
    }
    if (!release_jbytearray(env, buf, cbuf)) {
        return -1;
    }

    return res;
}
