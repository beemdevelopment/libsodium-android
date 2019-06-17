package com.beemdevelopment.sodium.util;

import java.io.Closeable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public final class DirectMemory implements Closeable {
    private final List<ByteBuffer> _bufs = new ArrayList<>();

    /**
     * Allocates a direct ByteBuffer of the given size.
     */
    public ByteBuffer allocate(int size) {
        ByteBuffer buf = ByteBuffer.allocateDirect(size);
        _bufs.add(buf);
        return buf;
    }

    /**
     * Allocates a direct ByteBuffer and copies the given data to it.
     */
    public ByteBuffer wrap(byte[] data) {
        return allocate(data.length).put(data);
    }

    /**
     * Closes this DirectMemory instance by clearing all allocated ByteBuffers.
     */
    @Override
    public void close() {
        for (ByteBuffer buf : _bufs) {
            clear(buf);
        }
    }

    /**
     * Clears the given ByteBuffer and overwrites the contents with zeroes.
     */
    private static void clear(ByteBuffer buf) {
        int len = buf.limit();
        buf.clear();

        for (int i = 0; i < len; i++) {
            buf.put((byte) 0);
        }
    }
}
