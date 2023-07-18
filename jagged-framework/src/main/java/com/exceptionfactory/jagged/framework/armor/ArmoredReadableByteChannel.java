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

    private final ByteBuffer characterBuffer = ByteBuffer.allocate(1);

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
            if (decodedBuffer.hasRemaining()) {
                outputBuffer.put(decodedBuffer.get());
                read++;
            } else if (footerFound) {
                read = END_OF_FILE;
                break;
            } else {
                readLineDecoded();
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
        lineBuffer.flip();
        // Skip whitespace prior to header
        while (lineBuffer.remaining() == 0) {
            readInputChannelLineBuffer();
            if (isLineBufferBlank() && lineBuffer.limit() > 0) {
                lineBuffer.clear();
                lineBuffer.flip();
            }
        }

        if (lineBuffer.remaining() == ArmoredIndicator.HEADER.getLength()) {
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

    private boolean isLineBufferBlank() {
        boolean blank = true;

        lineBuffer.mark();
        while (lineBuffer.hasRemaining()) {
            final byte character = lineBuffer.get();
            if (!Character.isWhitespace(character)) {
                blank = false;
                break;
            }
        }
        lineBuffer.reset();

        return blank;
    }

    private void readLineDecoded() throws IOException {
        readInputChannelLineBuffer();

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

    private void readInputChannelLineBuffer() throws IOException {
        lineBuffer.clear();

        byte character = readInputByte();
        while (character != END_OF_FILE) {
            if (ArmoredSeparator.LINE_FEED.getCode() == character) {
                break;
            } else if (ArmoredSeparator.CARRIAGE_RETURN.getCode() != character) {
                if (lineBuffer.hasRemaining()) {
                    lineBuffer.put(character);
                } else {
                    throw new ArmoredDecodingException(String.format("Maximum line length [%d] exceeded", MAXIMUM_LINE_LENGTH));
                }
            }

            character = readInputByte();
        }

        lineBuffer.flip();
    }

    private void readEnd() throws IOException {
        byte character = readInputByte();
        while (Character.isWhitespace(character)) {
            character = readInputByte();
        }

        if (END_OF_FILE != character) {
            throw new ArmoredDecodingException(String.format("Character [%d] found after Footer", character));
        }
    }

    private byte readInputByte() throws IOException {
        characterBuffer.clear();

        boolean endFound = false;
        while (characterBuffer.hasRemaining()) {
            final int read = inputChannel.read(characterBuffer);
            if (END_OF_FILE == read) {
                endFound = true;
                break;
            }
        }

        final byte inputByte;
        if (endFound) {
            inputByte = END_OF_FILE;
        } else {
            characterBuffer.flip();
            inputByte = characterBuffer.get();
        }

        return inputByte;
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
