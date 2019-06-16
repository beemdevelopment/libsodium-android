package com.beemdevelopment.sodium;

import java.io.Serializable;
import java.security.SecureRandom;

public final class SCrypt {
    private SCrypt() {

    }

    public static byte[] deriveKey(byte[] password, Parameters params) {
        CostParameters cost = params.getCost();
        byte[] key = new byte[params.getKeyLen()];
        Sodium.crypto_pwhash_scryptsalsa208sha256_ll(password, params.getSalt(), cost.N, cost.r, cost.p, key);
        return key;
    }

    public static final class CostParameters implements Serializable {
        public final long N;
        public final int r;
        public final int p;

        // https://blog.filippo.io/the-scrypt-parameters/#parametersfor2017
        public static final CostParameters PRESET_ENCRYPTION = new CostParameters(1 << 20, 8, 1);
        public static final CostParameters PRESET_INTERACTIVE = new CostParameters(1 << 15, 8, 1);

        public CostParameters(long n, int r, int p) {
            N = n;
            this.r = r;
            this.p = p;
        }
    }

    public static final class Parameters implements Serializable {
        private final CostParameters _cost;
        private final byte[] _salt;
        private final int _keyLen;

        public Parameters(CostParameters cost, byte[] salt, int keyLen) {
            _cost = cost;
            _salt = salt;
            _keyLen = keyLen;
        }

        public CostParameters getCost() {
            return _cost;
        }

        public byte[] getSalt() {
            return _salt;
        }

        public int getKeyLen() {
            return _keyLen;
        }

        public static Parameters generate(CostParameters cost, int saltLen, int keyLen) {
            byte[] salt = new byte[saltLen];
            new SecureRandom().nextBytes(salt);
            return new Parameters(cost, salt, keyLen);
        }
    }
}
