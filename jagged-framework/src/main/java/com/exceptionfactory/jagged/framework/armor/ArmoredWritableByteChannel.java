/*
 * Copyright 2023 Jagged Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.exceptionfactory.jagged.framework.armor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.Base64;
import java.util.Objects;

/**
 * Writable Byte Channel supporting age encryption files with Base64 according to strict PEM encoding described in RFC 7468 Section 3
 */
public class ArmoredWritableByteChannel implements WritableByteChannel {
    private static final int HEADER_BUFFER_LENGTH = 36;

    private static final int FOOTER_BUFFER_LENGTH = 34;

    private static final int MAXIMUM_SOURCE_LINE_LENGTH = 48;

    private static final byte LINE_FEED = (byte) ArmoredSeparator.LINE_FEED.getCode();

    private static final byte[] LINE_FEED_BYTES = new byte[]{LINE_FEED};

    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    private final ByteBuffer lastLineBuffer = ByteBuffer.allocate(MAXIMUM_SOURCE_LINE_LENGTH);

    private final WritableByteChannel outputChannel;

    /**
     * Armored Writable Byte Channel constructor wraps provided Output Channel
     *
     * @param outputChannel Output Channel for encoding bytes
     * @throws IOException Throw on failures writing age header
     */
    public ArmoredWritableByteChannel(final WritableByteChannel outputChannel) throws IOException {
        this.outputChannel = Objects.requireNonNull(outputChannel, "Output Channel required");
        writeHeader();
    }

    /**
     * Encode provided source buffer using Base64 without padding and write encoded bytes to output channel
     *
     * @param sourceBuffer Source Buffer to be encoded and written
     * @return Bytes read from source buffer and written to output channel
     * @throws IOException Thrown on failures writing to output channel
     */
    @Override
    public int write(final ByteBuffer sourceBuffer) throws IOException {
        Objects.requireNonNull(sourceBuffer, "Source Buffer required");
        final int sourceBufferLimit = sourceBuffer.limit();

        int sourceBufferLimitPosition = sourceBuffer.position();
        while (sourceBuffer.hasRemaining()) {
            final int lastLineBufferRemaining = lastLineBuffer.remaining();
            if (sourceBuffer.remaining() >= lastLineBufferRemaining) {
                sourceBufferLimitPosition += lastLineBufferRemaining;
                sourceBuffer.limit(sourceBufferLimitPosition);
                lastLineBuffer.put(sourceBuffer);
                sourceBuffer.limit(sourceBufferLimit);

                writeEncodedLineBuffer();
            } else {
                lastLineBuffer.put(sourceBuffer);
            }
        }

        return sourceBufferLimit;
    }

    /**
     * Return Channel open status
     *
     * @return Channel open status according to output channel
     */
    @Override
    public boolean isOpen() {
        return outputChannel.isOpen();
    }

    /**
     * Close Channel after writing PEM footer and line feed
     *
     * @throws IOException Thrown on failures writing footer or closing output channel
     */
    @Override
    public void close() throws IOException {
        if (lastLineBuffer.position() > 0) {
            writeEncodedLineBuffer();
        }

        final ByteBuffer footerBuffer = ByteBuffer.allocate(FOOTER_BUFFER_LENGTH);
        footerBuffer.put(ArmoredIndicator.FOOTER.getIndicator());
        footerBuffer.put(LINE_FEED);
        footerBuffer.flip();

        outputChannel.write(footerBuffer);
        outputChannel.close();
    }

    private void writeHeader() throws IOException {
        final ByteBuffer headerBuffer = ByteBuffer.allocate(HEADER_BUFFER_LENGTH);
        headerBuffer.put(ArmoredIndicator.HEADER.getIndicator());
        headerBuffer.put(LINE_FEED);
        headerBuffer.flip();

        outputChannel.write(headerBuffer);
    }

    private void writeEncodedLineBuffer() throws IOException {
        lastLineBuffer.flip();
        final ByteBuffer encodedBuffer = ENCODER.encode(lastLineBuffer);
        lastLineBuffer.clear();
        writeBuffer(encodedBuffer);

        final ByteBuffer lineFeedBuffer = ByteBuffer.wrap(LINE_FEED_BYTES);
        writeBuffer(lineFeedBuffer);
    }

    private void writeBuffer(final ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            outputChannel.write(buffer);
        }
    }
}
