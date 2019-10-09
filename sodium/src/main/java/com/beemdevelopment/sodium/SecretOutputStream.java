package com.beemdevelopment.sodium;

import com.beemdevelopment.sodium.util.DirectMemory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.LongBuffer;

import static com.beemdevelopment.sodium.SecretStream.CHUNK_SIZE;
import static com.beemdevelopment.sodium.Sodium.SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;

public class SecretOutputStream extends OutputStream {
    private OutputStream _outStream;

    private DirectMemory _mem;
    private ByteBuffer _state;
    private ByteBuffer _bufIn;
    private ByteBuffer _bufOut;
    private LongBuffer _lenBuf;

    public SecretOutputStream(OutputStream stream, byte[] key) throws IOException {
        _outStream = stream;

        // allocate a couple of direct buffers for input/output data
        _mem = new DirectMemory();
        _state = _mem.allocate(Sodium.SECRETSTREAM_XCHACHA20POLY1305_STATE_BYTES);
        _bufIn = _mem.allocate(CHUNK_SIZE);
        _bufOut = _mem.allocate(CHUNK_SIZE + Sodium.SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
        _bufOut.flip();
        _lenBuf = _mem.allocate(8 /* 64 bits */).order(ByteOrder.nativeOrder()).asLongBuffer();

        // initialize the stream state and header with the key
        ByteBuffer keyBuf = _mem.wrap(key);
        ByteBuffer header = _mem.allocate(Sodium.SECRETSTREAM_XCHACHA20POLY1305_HEADER_BYTES);
        SodiumJNI.crypto_secretstream_xchacha20poly1305_init_push(_state, header, keyBuf);

        // write the header to the output stream
        while (header.hasRemaining()) {
            _outStream.write(header.get());
        }
    }

    @Override
    public void write(int b) throws IOException {
        _bufIn.put((byte) b);

        if (!_bufIn.hasRemaining()) {
            flush();
        }
    }

    @Override
    public void flush() throws IOException {
        flush(false);
    }

    private void flush(boolean eof) throws IOException {
        // only flush if there's a full chunk or an EOF chunk to write
        if (_bufIn.hasRemaining() && !eof) {
            return;
        }

        byte tag = eof ? Sodium.SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
        SodiumJNI.crypto_secretstream_xchacha20poly1305_push(_state, _bufOut, _lenBuf, _bufIn, _bufIn.position(), null, 0, tag);
        _bufIn.clear();

        _bufOut.limit((int) _lenBuf.get(0));
        byte[] output = new byte[_bufOut.limit()];
        _bufOut.get(output);
        _bufOut.clear();
        _lenBuf.clear();

        // finally, write the ciphertext to the output stream
        _outStream.write(output);
    }

    @Override
    public void close() throws IOException {
        // flush any leftover input buffer data and write the final tag
        flush(true);

        // clear all of the direct buffers
        _mem.close();
    }
}
