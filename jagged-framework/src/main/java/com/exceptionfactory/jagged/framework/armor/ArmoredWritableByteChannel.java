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
final class ArmoredWritableByteChannel implements WritableByteChannel {
    private static final int HEADER_BUFFER_LENGTH = 36;

    private static final int FOOTER_BUFFER_LENGTH = 34;

    private static final int MAXIMUM_SOURCE_LINE_LENGTH = 48;

    private static final int MAXIMUM_ENCODED_LINE_LENGTH = 64;

    private static final int CHUNK_LENGTH = 66560;

    private static final int START_POSITION = 0;

    private static final byte LINE_FEED = ArmoredSeparator.LINE_FEED.getCode();

    private static final byte[] LINE_FEED_BYTES = new byte[]{LINE_FEED};

    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    private final ByteBuffer lineFeedBuffer = ByteBuffer.wrap(LINE_FEED_BYTES);

    private final ByteBuffer lineBuffer = ByteBuffer.allocate(MAXIMUM_SOURCE_LINE_LENGTH);

    private final ByteBuffer chunkBuffer = ByteBuffer.allocate(CHUNK_LENGTH);

    private final WritableByteChannel outputChannel;

    /**
     * Armored Writable Byte Channel constructor wraps provided Output Channel
     *
     * @param outputChannel Output Channel for encoding bytes
     * @throws IOException Throw on failures writing age header
     */
    ArmoredWritableByteChannel(final WritableByteChannel outputChannel) throws IOException {
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
        putLineBuffer(sourceBuffer);

        if (lineBuffer.position() == 0) {
            final int sourceBufferRemaining = sourceBuffer.remaining();
            final int sourceBufferLineModulus = sourceBufferRemaining % MAXIMUM_SOURCE_LINE_LENGTH;

            if (sourceBufferLineModulus > 0) {
                final int sourceBufferLimitAdjusted = sourceBufferLimit - sourceBufferLineModulus;
                sourceBuffer.limit(sourceBufferLimitAdjusted);
            }

            final ByteBuffer encodedSourceBuffer = ENCODER.encode(sourceBuffer);
            writeEncodedBuffer(encodedSourceBuffer);

            sourceBuffer.limit(sourceBufferLimit);
            putLineBuffer(sourceBuffer);
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
        if (lineBuffer.position() > 0) {
            writeLineBuffer();
        }

        writeFooter();
        outputChannel.close();
    }

    private void writeHeader() throws IOException {
        final ByteBuffer headerBuffer = ByteBuffer.allocate(HEADER_BUFFER_LENGTH);
        headerBuffer.put(ArmoredIndicator.HEADER.getIndicator());
        headerBuffer.put(LINE_FEED);
        headerBuffer.flip();

        writeBuffer(headerBuffer);
    }

    private void writeFooter() throws IOException {
        final ByteBuffer footerBuffer = ByteBuffer.allocate(FOOTER_BUFFER_LENGTH);
        footerBuffer.put(ArmoredIndicator.FOOTER.getIndicator());
        footerBuffer.put(LINE_FEED);
        footerBuffer.flip();

        writeBuffer(footerBuffer);
    }

    private void writeEncodedBuffer(final ByteBuffer encodedBuffer) throws IOException {
        final int encodedBufferLimit = encodedBuffer.limit();

        while (encodedBuffer.hasRemaining()) {
            while (chunkBuffer.hasRemaining()) {
                final int limit = encodedBuffer.position() + MAXIMUM_ENCODED_LINE_LENGTH;
                encodedBuffer.limit(limit);

                chunkBuffer.put(encodedBuffer);
                encodedBuffer.limit(encodedBufferLimit);

                chunkBuffer.put(lineFeedBuffer);
                lineFeedBuffer.position(START_POSITION);

                if (encodedBuffer.remaining() == 0) {
                    break;
                }
            }

            chunkBuffer.flip();
            writeBuffer(chunkBuffer);
            chunkBuffer.clear();

            encodedBuffer.limit(encodedBufferLimit);
        }
    }

    private void writeLineBuffer() throws IOException {
        lineBuffer.flip();

        final ByteBuffer encodedLineBuffer = ENCODER.encode(lineBuffer);
        writeBuffer(encodedLineBuffer);

        writeBuffer(lineFeedBuffer);
        lineFeedBuffer.position(START_POSITION);
    }

    private void writeBuffer(final ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            outputChannel.write(buffer);
        }
    }

    private void putLineBuffer(final ByteBuffer sourceBuffer) throws IOException {
        final int lineBufferRemaining = lineBuffer.remaining();

        if (lineBufferRemaining > sourceBuffer.remaining()) {
            lineBuffer.put(sourceBuffer);
        } else if (lineBuffer.position() > START_POSITION) {
            final int sourceBufferLimit = sourceBuffer.limit();

            if (sourceBuffer.remaining() > lineBufferRemaining) {
                final int sourceBufferLimitAdjusted = sourceBuffer.position() + lineBufferRemaining;
                sourceBuffer.limit(sourceBufferLimitAdjusted);
            }

            lineBuffer.put(sourceBuffer);
            sourceBuffer.limit(sourceBufferLimit);
        }

        if (lineBuffer.position() == MAXIMUM_SOURCE_LINE_LENGTH) {
            writeLineBuffer();
            lineBuffer.clear();
        }
    }
}
