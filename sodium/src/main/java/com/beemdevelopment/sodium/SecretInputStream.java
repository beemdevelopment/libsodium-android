package com.beemdevelopment.sodium;

import com.beemdevelopment.sodium.util.DirectMemory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.LongBuffer;

import static com.beemdevelopment.sodium.SecretStream.CHUNK_SIZE;
import static com.beemdevelopment.sodium.Sodium.SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;

public class SecretInputStream extends InputStream {
    private InputStream _inStream;

    private DirectMemory _mem;
    private ByteBuffer _state;
    private ByteBuffer _bufIn;
    private ByteBuffer _bufOut;
    private LongBuffer _lenBuf;
    private ByteBuffer _tagBuf;
    private boolean _readFinal;

    public SecretInputStream(InputStream stream, byte[] key)
            throws IOException, SodiumIntegrityException {
        _inStream = stream;

        _mem = new DirectMemory();
        _state = _mem.allocate(Sodium.SECRETSTREAM_XCHACHA20POLY1305_STATE_BYTES);
        _bufIn = _mem.allocate(CHUNK_SIZE + Sodium.SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
        _bufOut = _mem.allocate(CHUNK_SIZE);
        _bufOut.flip();
        _lenBuf = _mem.allocate(8 /* uint64_t */).order(ByteOrder.nativeOrder()).asLongBuffer();
        _tagBuf = _mem.allocate(1 /* uint8_t */);

        // read the header, verify it and initialize the secret steam state
        ByteBuffer header = _mem.allocate(Sodium.SECRETSTREAM_XCHACHA20POLY1305_HEADER_BYTES);
        while (_inStream.available() > 0 && header.hasRemaining()) {
            header.put((byte) _inStream.read());
        }
        ByteBuffer keyBuf = _mem.wrap(key);
        if (header.hasRemaining() || SodiumJNI.crypto_secretstream_xchacha20poly1305_init_pull(_state, header, keyBuf) != 0) {
            throw new SodiumIntegrityException("Incomplete header");
        }
    }

    @Override
    public int read() throws IOException {
        // check whether there are still some decrypted bytes in the buffer
        if (!_bufOut.hasRemaining()) {
            // if not, and we've encountered the final tag, we're done
            if (_readFinal) {
                return -1;
            }

            // if not, read a new chunk from the input stream and decrypt it
            try {
                readNextChunk();
            } catch (SodiumIntegrityException e) {
                throw new IOException(e);
            }
        }

        // retrieve the next byte from the buffer
        return _bufOut.get();
    }

    private void readNextChunk() throws IOException, SodiumIntegrityException {
        _bufIn.clear();
        while (_inStream.available() > 0 && _bufIn.hasRemaining()) {
            _bufIn.put((byte) _inStream.read());
        }

        // if we couldn't read anything from the input stream
        // and we haven't encountered the final tag yet, something is wrong
        if (_bufIn.position() == 0) {
            throw new SodiumIntegrityException("Unexpected end of secret stream");
        }

        _bufOut.clear();
        if (SodiumJNI.crypto_secretstream_xchacha20poly1305_pull(_state, _bufOut, _lenBuf, _tagBuf, _bufIn, _bufIn.position(), null, 0) != 0) {
            throw new SodiumIntegrityException("Corrupted chunk in secret stream");
        }
        _bufOut.limit((int) _lenBuf.get(0));
        _lenBuf.clear();

        if (_tagBuf.get(0) == SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
            _readFinal = true;
            if (_inStream.available() > 0) {
                throw new SodiumIntegrityException("Secret stream ended before input stream");
            }
        }
    }

    @Override
    public int available() {
        if (_bufOut.hasRemaining()) {
            return _bufOut.remaining();
        }

        // TODO: be more accurate
        return _readFinal ? -1 : 1;
    }

    @Override
    public void close() {
        _mem.close();
    }
}
