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
final class ArmoredReadableByteChannel implements ReadableByteChannel {
    /** Base64 Decoder supports padding characters */
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    /** Base64 Encoder with padding characters */
    private static final Base64.Encoder ENCODER_WITH_PADDING = Base64.getEncoder();

    /** End of file indicator */
    private static final byte END_OF_FILE = -1;

    /** Maximum length of Base64 encoded line without carriage return or line feed endings */
    private static final int MAXIMUM_LINE_LENGTH = 64;

    /** Maximum length of Base64 encoded line terminated with carriage return and line feed */
    private static final int MAXIMUM_TERMINATED_LINE_LENGTH = 66;

    /** Input Buffer containing up to 1024 encoded contiguous lines with line feed endings */
    private static final int INPUT_BUFFER_CAPACITY = 66560;

    /** Encoded Buffer containing up to 1024 encoded contiguous lines without line endings */
    private static final int ENCODED_BUFFER_CAPACITY = 65536;

    /** Decoded Buffer containing up to 1024 decoded contiguous lines */
    private static final int DECODED_BUFFER_CAPACITY = 49152;

    private static final byte LINE_FEED = ArmoredSeparator.LINE_FEED.getCode();

    private static final byte CARRIAGE_RETURN = ArmoredSeparator.CARRIAGE_RETURN.getCode();

    private final ByteBuffer inputBuffer = ByteBuffer.allocate(INPUT_BUFFER_CAPACITY);

    private final ByteBuffer encodedBuffer = ByteBuffer.allocate(ENCODED_BUFFER_CAPACITY);

    private final ByteBuffer decodedBuffer = ByteBuffer.allocate(DECODED_BUFFER_CAPACITY);

    private final ByteBuffer lineBuffer = ByteBuffer.allocate(MAXIMUM_LINE_LENGTH);

    private final ReadableByteChannel inputChannel;

    private boolean lastEncodedLineFound;

    /**
     * Armored Readable Byte Channel constructor reads from an input channel and decodes bytes after validating age header
     *
     * @param inputChannel Input Channel containing armored age encryption with standard header and footer
     * @throws IOException Thrown on failures reading or validating required header
     */
    ArmoredReadableByteChannel(final ReadableByteChannel inputChannel) throws IOException {
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
        readInputChannel();
        readLeading();
        readLineBuffer();
        if (lineBuffer.limit() == ArmoredIndicator.HEADER.getLength()) {
            final byte[] header = getLineEncoded();
            if (Arrays.equals(ArmoredIndicator.HEADER.getIndicator(), header)) {
                readEncodedBuffer();
            } else {
                throw new ArmoredDecodingException("Header not matched");
            }
        } else {
            throw new ArmoredDecodingException("Header not found");
        }
    }

    private void readLeading() {
        inputBuffer.mark();
        byte character = inputBuffer.get();
        while (Character.isWhitespace(character)) {
            inputBuffer.mark();
            character = inputBuffer.get();
        }
        inputBuffer.reset();
    }

    private void readTrailing() throws IOException {
        while (inputBuffer.hasRemaining()) {
            final byte character = inputBuffer.get();
            if (!Character.isWhitespace(character)) {
                throw new ArmoredDecodingException(String.format("Character [%d] found after Footer", character));
            }
        }
    }

    private int readDecodedBuffer(final ByteBuffer outputBuffer) throws IOException {
        int read = END_OF_FILE;
        if (decodedBuffer.hasRemaining()) {
            read++;
        }

        while (decodedBuffer.hasRemaining()) {
            final int decodedBufferLimit = decodedBuffer.limit();

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

                if (decodedBuffer.remaining() == 0) {
                    readEncodedBuffer();
                }
            } else {
                break;
            }
        }

        if (decodedBuffer.remaining() == 0) {
            read = END_OF_FILE;
        }

        return read;
    }

    private void readEncodedBuffer() throws IOException {
        decodedBuffer.clear();

        while (decodedBuffer.hasRemaining()) {
            readInputBuffer();

            if (encodedBuffer.hasRemaining()) {
                processEncodedBuffer();
            } else {
                readLastLineBuffer();
                break;
            }
        }

        decodedBuffer.flip();
    }

    private void processEncodedBuffer() throws ArmoredDecodingException {
        if (encodedBuffer.limit() == ENCODED_BUFFER_CAPACITY) {
            // Run decoding using buffer arrays
            decodeEncodedBuffer();
            decodedBuffer.position(DECODED_BUFFER_CAPACITY);
        } else {
            final ByteBuffer decoded = getDecodedBuffer();
            decodedBuffer.put(decoded);
            readLastLineBuffer();
        }
    }

    private void readInputBuffer() throws IOException {
        encodedBuffer.clear();

        while (encodedBuffer.hasRemaining()) {
            readLineBuffer();

            if (lineBuffer.limit() == MAXIMUM_LINE_LENGTH) {
                if (lastEncodedLineFound) {
                    final String message = String.format("Short line less than standard length [%d] found before last line", MAXIMUM_LINE_LENGTH);
                    throw new ArmoredDecodingException(message);
                }
                encodedBuffer.put(lineBuffer);
                lineBuffer.clear();
            } else if (lineBuffer.limit() == ArmoredIndicator.FOOTER.getLength()) {
                readFooter();
                break;
            } else if (lineBuffer.limit() == 0) {
                throw new ArmoredDecodingException("Empty line found before Footer");
            } else {
                break;
            }
        }

        encodedBuffer.flip();
    }

    private void readLastLineBuffer() throws ArmoredDecodingException {
        // Decode line buffer when length is less than maximum length indicating last line before footer
        if (lineBuffer.hasRemaining()) {
            final byte[] lineEncoded = getLineEncoded();
            final byte[] decoded = getDecoded(lineEncoded);
            final byte[] encodedWithPadding = ENCODER_WITH_PADDING.encode(decoded);

            if (Arrays.equals(encodedWithPadding, lineEncoded)) {
                decodedBuffer.put(decoded);
            } else {
                throw new ArmoredDecodingException("Base64 canonical padding not found");
            }

            lastEncodedLineFound = true;
        }
    }

    private void readFooter() throws IOException {
        final byte[] footer = new byte[ArmoredIndicator.FOOTER.getLength()];
        lineBuffer.get(footer);
        if (Arrays.equals(ArmoredIndicator.FOOTER.getIndicator(), footer)) {
            readTrailing();
        } else {
            lineBuffer.rewind();
        }
    }

    private void readLineBuffer() throws IOException {
        if (inputBuffer.remaining() < MAXIMUM_TERMINATED_LINE_LENGTH) {
            inputBuffer.compact();
            readInputChannel();
        }

        final int readBufferRemaining = Math.min(inputBuffer.remaining(), MAXIMUM_LINE_LENGTH);
        for (int i = 0; i < readBufferRemaining; i++) {
            final byte character = inputBuffer.get();
            if (LINE_FEED == character) {
                break;
            } else if (CARRIAGE_RETURN == character) {
                final byte endCharacter = inputBuffer.get();
                if (LINE_FEED == endCharacter) {
                    break;
                }
                throw new ArmoredDecodingException(String.format("Line Feed [%d] character not found after Carriage Return", LINE_FEED));
            } else {
                lineBuffer.put(character);
            }
        }

        if (lineBuffer.position() == MAXIMUM_LINE_LENGTH) {
            final byte character = inputBuffer.get();
            if (LINE_FEED == character) {
                lineBuffer.flip();
            } else if (CARRIAGE_RETURN == character) {
                final byte endCharacter = inputBuffer.get();
                if (LINE_FEED == endCharacter) {
                    lineBuffer.flip();
                } else {
                    throw new ArmoredDecodingException(String.format("Line Feed [%d] character not found after Carriage Return", LINE_FEED));
                }
            } else {
                throw new ArmoredDecodingException(String.format("Maximum line length [%d] exceeded", MAXIMUM_LINE_LENGTH));
            }
        } else {
            lineBuffer.flip();
        }
    }

    private void readInputChannel() throws IOException {
        while (inputBuffer.hasRemaining()) {
            final int read = inputChannel.read(inputBuffer);
            if (END_OF_FILE == read) {
                break;
            }
        }

        inputBuffer.flip();
    }

    private byte[] getLineEncoded() {
        final byte[] lineEncoded = new byte[lineBuffer.limit()];
        lineBuffer.get(lineEncoded);
        lineBuffer.clear();
        return lineEncoded;
    }

    private byte[] getDecoded(final byte[] encoded) throws ArmoredDecodingException {
        try {
            return DECODER.decode(encoded);
        } catch (final IllegalArgumentException e) {
            throw new ArmoredDecodingException("Base64 line decoding failed", e);
        }
    }

    private ByteBuffer getDecodedBuffer() throws ArmoredDecodingException {
        try {
            return DECODER.decode(encodedBuffer);
        } catch (final IllegalArgumentException e) {
            throw new ArmoredDecodingException("Base64 buffer decoding failed", e);
        }
    }

    private void decodeEncodedBuffer() throws ArmoredDecodingException {
        try {
            DECODER.decode(encodedBuffer.array(), decodedBuffer.array());
        } catch (final IllegalArgumentException e) {
            throw new ArmoredDecodingException("Base64 decoding failed", e);
        }
    }
}
