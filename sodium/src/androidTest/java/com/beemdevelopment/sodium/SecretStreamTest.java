package com.beemdevelopment.sodium;

import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class SecretStreamTest {
    static {
        Sodium.init();
    }

    @Test
    public void testEncryptDecrypt() throws IOException, SodiumIntegrityException {
        byte[] key = SecretStream.generateKey();
        String message = "this is a secret message";

        // encrypt the message with a random key
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        try (SecretOutputStream secretStream = new SecretOutputStream(outStream, key)) {
            try (ByteArrayInputStream inStream = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8))) {
                pipe(secretStream, inStream);
            }
        }
        byte[] ciphertext = outStream.toByteArray();

        // decrypt the cipher text
        outStream.reset();
        try (ByteArrayInputStream inStream = new ByteArrayInputStream(ciphertext)) {
            try (SecretInputStream secretStream = new SecretInputStream(inStream, key)) {
                pipe(outStream, secretStream);
            }
        }

        assertEquals(message, new String(outStream.toByteArray(), StandardCharsets.UTF_8));
    }

    @Test
    public void benchEncrypt() throws IOException {
        int factor = 1000;
        byte[] zeroes = new byte[10000];
        byte[] key = SecretStream.generateKey();

        long start = System.currentTimeMillis();
        try (SecretOutputStream secretStream = new SecretOutputStream(new NullOutputStream(), key)) {
            for (int count = 0; count < zeroes.length * factor; count += zeroes.length) {
                secretStream.write(zeroes);
            }
        }

        long elapsed = System.currentTimeMillis() - start;
        Log.i("SecretStreamTest", String.format("XChaCha20Poly1305 performance: %.2f MB/s", (zeroes.length * factor / 1000 / 1000) / ((float) elapsed / 1000)));
    }

    @Test
    public void benchDecrypt() throws IOException {

    }

    private static void pipe(OutputStream outStream, InputStream inStream) throws IOException {
        int read;
        byte[] buf = new byte[4096];
        while ((read = inStream.read(buf, 0, buf.length)) != -1) {
            outStream.write(buf, 0, read);
        }
    }

    private static class NullOutputStream extends OutputStream {
        @Override
        public void write(int b) throws IOException {

        }
    }
}