package com.beemdevelopment.sodium;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class SCryptTest {
    static {
        Sodium.init();
    }

    private static class Vector {
        public String Password;
        public String Salt;
        public int N;
        public int r;
        public int p;
        public byte[] Key;

        public Vector(String password, String salt, int n, int r, int p, byte[] key) {
            Password = password;
            Salt = salt;
            N = n;
            this.r = r;
            this.p = p;
            Key = key;
        }
    }

    private static Vector[] _vectors = new Vector[]{
            new Vector("", "", 1 << 4, 1, 1, new byte[]{
                    (byte) 0x77, (byte) 0xd6, (byte) 0x57, (byte) 0x62,
                    (byte) 0x38, (byte) 0x65, (byte) 0x7b, (byte) 0x20,
                    (byte) 0x3b, (byte) 0x19, (byte) 0xca, (byte) 0x42,
                    (byte) 0xc1, (byte) 0x8a, (byte) 0x04, (byte) 0x97,
                    (byte) 0xf1, (byte) 0x6b, (byte) 0x48, (byte) 0x44,
                    (byte) 0xe3, (byte) 0x07, (byte) 0x4a, (byte) 0xe8,
                    (byte) 0xdf, (byte) 0xdf, (byte) 0xfa, (byte) 0x3f,
                    (byte) 0xed, (byte) 0xe2, (byte) 0x14, (byte) 0x42,
                    (byte) 0xfc, (byte) 0xd0, (byte) 0x06, (byte) 0x9d,
                    (byte) 0xed, (byte) 0x09, (byte) 0x48, (byte) 0xf8,
                    (byte) 0x32, (byte) 0x6a, (byte) 0x75, (byte) 0x3a,
                    (byte) 0x0f, (byte) 0xc8, (byte) 0x1f, (byte) 0x17,
                    (byte) 0xe8, (byte) 0xd3, (byte) 0xe0, (byte) 0xfb,
                    (byte) 0x2e, (byte) 0x0d, (byte) 0x36, (byte) 0x28,
                    (byte) 0xcf, (byte) 0x35, (byte) 0xe2, (byte) 0x0c,
                    (byte) 0x38, (byte) 0xd1, (byte) 0x89, (byte) 0x06
            }),
            new Vector("password", "NaCl", 1 << 10, 8, 16, new byte[]{
                    (byte) 0xfd, (byte) 0xba, (byte) 0xbe, (byte) 0x1c,
                    (byte) 0x9d, (byte) 0x34, (byte) 0x72, (byte) 0x00,
                    (byte) 0x78, (byte) 0x56, (byte) 0xe7, (byte) 0x19,
                    (byte) 0x0d, (byte) 0x01, (byte) 0xe9, (byte) 0xfe,
                    (byte) 0x7c, (byte) 0x6a, (byte) 0xd7, (byte) 0xcb,
                    (byte) 0xc8, (byte) 0x23, (byte) 0x78, (byte) 0x30,
                    (byte) 0xe7, (byte) 0x73, (byte) 0x76, (byte) 0x63,
                    (byte) 0x4b, (byte) 0x37, (byte) 0x31, (byte) 0x62,
                    (byte) 0x2e, (byte) 0xaf, (byte) 0x30, (byte) 0xd9,
                    (byte) 0x2e, (byte) 0x22, (byte) 0xa3, (byte) 0x88,
                    (byte) 0x6f, (byte) 0xf1, (byte) 0x09, (byte) 0x27,
                    (byte) 0x9d, (byte) 0x98, (byte) 0x30, (byte) 0xda,
                    (byte) 0xc7, (byte) 0x27, (byte) 0xaf, (byte) 0xb9,
                    (byte) 0x4a, (byte) 0x83, (byte) 0xee, (byte) 0x6d,
                    (byte) 0x83, (byte) 0x60, (byte) 0xcb, (byte) 0xdf,
                    (byte) 0xa2, (byte) 0xcc, (byte) 0x06, (byte) 0x40
            }),
            new Vector("pleaseletmein", "SodiumChloride", 1 << 14, 8, 1, new byte[]{
                    (byte) 0x70, (byte) 0x23, (byte) 0xbd, (byte) 0xcb,
                    (byte) 0x3a, (byte) 0xfd, (byte) 0x73, (byte) 0x48,
                    (byte) 0x46, (byte) 0x1c, (byte) 0x06, (byte) 0xcd,
                    (byte) 0x81, (byte) 0xfd, (byte) 0x38, (byte) 0xeb,
                    (byte) 0xfd, (byte) 0xa8, (byte) 0xfb, (byte) 0xba,
                    (byte) 0x90, (byte) 0x4f, (byte) 0x8e, (byte) 0x3e,
                    (byte) 0xa9, (byte) 0xb5, (byte) 0x43, (byte) 0xf6,
                    (byte) 0x54, (byte) 0x5d, (byte) 0xa1, (byte) 0xf2,
                    (byte) 0xd5, (byte) 0x43, (byte) 0x29, (byte) 0x55,
                    (byte) 0x61, (byte) 0x3f, (byte) 0x0f, (byte) 0xcf,
                    (byte) 0x62, (byte) 0xd4, (byte) 0x97, (byte) 0x05,
                    (byte) 0x24, (byte) 0x2a, (byte) 0x9a, (byte) 0xf9,
                    (byte) 0xe6, (byte) 0x1e, (byte) 0x85, (byte) 0xdc,
                    (byte) 0x0d, (byte) 0x65, (byte) 0x1e, (byte) 0x40,
                    (byte) 0xdf, (byte) 0xcf, (byte) 0x01, (byte) 0x7b,
                    (byte) 0x45, (byte) 0x57, (byte) 0x58, (byte) 0x87
            }),
            new Vector("pleaseletmein", "SodiumChloride", 1 << 20, 8, 1, new byte[]{
                    (byte) 0x21, (byte) 0x01, (byte) 0xcb, (byte) 0x9b,
                    (byte) 0x6a, (byte) 0x51, (byte) 0x1a, (byte) 0xae,
                    (byte) 0xad, (byte) 0xdb, (byte) 0xbe, (byte) 0x09,
                    (byte) 0xcf, (byte) 0x70, (byte) 0xf8, (byte) 0x81,
                    (byte) 0xec, (byte) 0x56, (byte) 0x8d, (byte) 0x57,
                    (byte) 0x4a, (byte) 0x2f, (byte) 0xfd, (byte) 0x4d,
                    (byte) 0xab, (byte) 0xe5, (byte) 0xee, (byte) 0x98,
                    (byte) 0x20, (byte) 0xad, (byte) 0xaa, (byte) 0x47,
                    (byte) 0x8e, (byte) 0x56, (byte) 0xfd, (byte) 0x8f,
                    (byte) 0x4b, (byte) 0xa5, (byte) 0xd0, (byte) 0x9f,
                    (byte) 0xfa, (byte) 0x1c, (byte) 0x6d, (byte) 0x92,
                    (byte) 0x7c, (byte) 0x40, (byte) 0xf4, (byte) 0xc3,
                    (byte) 0x37, (byte) 0x30, (byte) 0x40, (byte) 0x49,
                    (byte) 0xe8, (byte) 0xa9, (byte) 0x52, (byte) 0xfb,
                    (byte) 0xcb, (byte) 0xf4, (byte) 0x5c, (byte) 0x6f,
                    (byte) 0xa7, (byte) 0x7a, (byte) 0x41, (byte) 0xa4
            })
    };

    @Test
    public void vectorsMatch() {
        for (Vector vector : _vectors) {
            byte[] salt = vector.Salt.getBytes(StandardCharsets.UTF_8);
            byte[] password = vector.Password.getBytes(StandardCharsets.UTF_8);

            SCrypt.CostParameters cost = new SCrypt.CostParameters(vector.N, vector.r, vector.p);
            SCrypt.Parameters params = new SCrypt.Parameters(cost, salt, 64);
            byte[] key = SCrypt.deriveKey(password, params);

            assertArrayEquals(key, vector.Key);
        }
    }
}
