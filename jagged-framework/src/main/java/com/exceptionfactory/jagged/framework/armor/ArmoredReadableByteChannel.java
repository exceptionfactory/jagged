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
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Readable Byte Channel supporting age encryption files encoded according to strict PEM encoding described in RFC 7468 Section 3
 */
public class ArmoredReadableByteChannel implements ReadableByteChannel {
    /** Base64 Decoder supports padding characters */
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    /** Base64 Encoder with padding characters */
    private static final Base64.Encoder ENCODER_WITH_PADDING = Base64.getEncoder();

    private static final byte END_OF_FILE = -1;

    private static final int MAXIMUM_LINE_LENGTH = 64;

    private static final int MAXIMUM_DECODED_LENGTH = 48;

    private static final int INPUT_BUFFER_CAPACITY = 65536;

    private final ByteBuffer inputBuffer = ByteBuffer.allocate(INPUT_BUFFER_CAPACITY);

    private final ByteBuffer decodedBuffer = ByteBuffer.allocate(MAXIMUM_DECODED_LENGTH);

    private final ByteBuffer lineBuffer = ByteBuffer.allocate(MAXIMUM_LINE_LENGTH);

    private final ReadableByteChannel inputChannel;

    private boolean lastEncodedLineFound;

    private boolean footerFound;

    /**
     * Armored Readable Byte Channel constructor reads from an input channel and decodes bytes after validating age header
     *
     * @param inputChannel Input Channel containing armored age encryption with standard header and footer
     * @throws IOException Thrown on failures reading or validating required header
     */
    public ArmoredReadableByteChannel(final ReadableByteChannel inputChannel) throws IOException {
        this.inputChannel = Objects.requireNonNull(inputChannel, "Input Channel required");
        readHeader();
    }

    /**
     * Read input Channel decoding armored characters and write bytes to provided output buffer
     *
     * @param outputBuffer
     *         The buffer into which bytes are to be transferred
     *
     * @return Number of bytes transferred to output buffer
     * @throws IOException Thrown on failures reading input Channel
     */
    @Override
    public int read(final ByteBuffer outputBuffer) throws IOException {
        Objects.requireNonNull(outputBuffer, "Output Buffer required");

        int read = 0;

        while (outputBuffer.hasRemaining()) {
            if (decodedBuffer.remaining() == 0) {
                if (footerFound) {
                    read = END_OF_FILE;
                    break;
                }
                readLineDecoded();
            }

            final int decodedBufferRead = readDecodedBuffer(outputBuffer);
            if (END_OF_FILE == decodedBufferRead) {
                read = END_OF_FILE;
                break;
            } else {
                read += decodedBufferRead;
            }
        }

        return read;
    }

    /**
     * Return Channel open status
     *
     * @return Channel open status according to input channel
     */
    @Override
    public boolean isOpen() {
        return inputChannel.isOpen();
    }

    /**
     * Close channel and clear buffers
     *
     * @throws IOException Thrown on failures to close input channel
     */
    @Override
    public void close() throws IOException {
        inputChannel.close();
    }

    private void readHeader() throws IOException {
        readInputBuffer();

        // Skip whitespace prior to header
        inputBuffer.mark();
        byte character = inputBuffer.get();
        while (Character.isWhitespace(character)) {
            inputBuffer.mark();
            character = inputBuffer.get();
        }
        inputBuffer.reset();

        readLineBuffer();
        if (lineBuffer.limit() == ArmoredIndicator.HEADER.getLength()) {
            final byte[] header = new byte[ArmoredIndicator.HEADER.getLength()];
            lineBuffer.get(header);

            if (Arrays.equals(ArmoredIndicator.HEADER.getIndicator(), header)) {
                readLineDecoded();
            } else {
                throw new ArmoredDecodingException("Header not matched");
            }
        } else {
            throw new ArmoredDecodingException("Header not found");
        }
    }

    private int readDecodedBuffer(final ByteBuffer outputBuffer) {
        int read = END_OF_FILE;
        if (decodedBuffer.hasRemaining()) {
            read++;
        }

        final int decodedBufferLimit = decodedBuffer.limit();

        while (decodedBuffer.hasRemaining()) {
            if (outputBuffer.hasRemaining()) {
                final int outputBufferRemaining = outputBuffer.remaining();
                final int decodedBufferRemaining = decodedBuffer.remaining();
                if (decodedBufferRemaining > outputBufferRemaining) {
                    final int decodedBufferInputLimit = decodedBuffer.position() + outputBufferRemaining;
                    decodedBuffer.limit(decodedBufferInputLimit);
                }

                final int decodedBufferStartPosition = decodedBuffer.position();

                outputBuffer.put(decodedBuffer);
                decodedBuffer.limit(decodedBufferLimit);

                final int decodedBufferRead = decodedBuffer.position() - decodedBufferStartPosition;
                read += decodedBufferRead;
            } else {
                break;
            }
        }
        return read;
    }

    private void readLineDecoded() throws IOException {
        readLineBuffer();

        if (lineBuffer.limit() == ArmoredIndicator.FOOTER.getLength()) {
            final byte[] footer = new byte[ArmoredIndicator.FOOTER.getLength()];
            lineBuffer.get(footer);
            if (Arrays.equals(ArmoredIndicator.FOOTER.getIndicator(), footer)) {
                footerFound = true;
                readEnd();
            } else {
                lineBuffer.rewind();
                decodeLineBuffer();
            }
        } else if (lineBuffer.limit() == 0) {
            throw new ArmoredDecodingException("Empty line found before Footer");
        } else {
            decodeLineBuffer();
        }
    }

    private void readLineBuffer() throws IOException {
        lineBuffer.clear();

        if (inputBuffer.remaining() == 0) {
            readInputBuffer();
        }
        while (inputBuffer.hasRemaining()) {
            final byte character = inputBuffer.get();
            if (ArmoredSeparator.LINE_FEED.getCode() == character) {
                break;
            } else if (ArmoredSeparator.CARRIAGE_RETURN.getCode() != character) {
                if (lineBuffer.hasRemaining()) {
                    lineBuffer.put(character);
                } else {
                    throw new ArmoredDecodingException(String.format("Maximum line length [%d] exceeded", MAXIMUM_LINE_LENGTH));
                }
            }

            if (inputBuffer.remaining() == 0) {
                readInputBuffer();
            }
        }

        lineBuffer.flip();
    }

    private void readEnd() throws IOException {
        while (inputBuffer.hasRemaining()) {
            final byte character = inputBuffer.get();
            if (!Character.isWhitespace(character)) {
                throw new ArmoredDecodingException(String.format("Character [%d] found after Footer", character));
            }
        }
    }

    private void readInputBuffer() throws IOException {
        inputBuffer.clear();

        while (inputBuffer.hasRemaining()) {
            final int read = inputChannel.read(inputBuffer);
            if (END_OF_FILE == read) {
                break;
            }
        }

        inputBuffer.flip();
    }

    private void decodeLineBuffer() throws ArmoredDecodingException {
        if (lineBuffer.limit() == MAXIMUM_LINE_LENGTH) {
            if (lastEncodedLineFound) {
                final String message = String.format("Short line less than standard length [%d] found before last line", MAXIMUM_LINE_LENGTH);
                throw new ArmoredDecodingException(message);
            }
        } else {
            lastEncodedLineFound = true;
        }

        decodedBuffer.clear();
        try {
            final ByteBuffer decoded = getDecodedLineBuffer();
            decodedBuffer.put(decoded);
        } catch (final IllegalArgumentException e) {
            throw new ArmoredDecodingException("Base64 line decoding failed", e);
        }
        decodedBuffer.flip();
    }

    private ByteBuffer getDecodedLineBuffer() throws ArmoredDecodingException {
        final ByteBuffer decoded;
        if (lastEncodedLineFound) {
            final byte[] encoded = new byte[lineBuffer.limit()];
            lineBuffer.get(encoded);

            final byte[] decodedBytes = DECODER.decode(encoded);
            final byte[] encodedWithPadding = ENCODER_WITH_PADDING.encode(decodedBytes);

            if (Arrays.equals(encodedWithPadding, encoded)) {
                decoded = ByteBuffer.wrap(decodedBytes);
            } else {
                throw new ArmoredDecodingException("Base64 canonical padding not found");
            }
        } else {
            decoded = DECODER.decode(lineBuffer);
        }

        return decoded;
    }
}
