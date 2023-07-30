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

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArmoredReadableByteChannelTest {
    private static final Charset CHARACTER_SET = StandardCharsets.UTF_8;

    private static final String BODY = "amFnZ2Vk";

    private static final byte[] BODY_DECODED = new byte[]{106, 97, 103, 103, 101, 100};

    private static final byte[] BODY_INVALID = new byte[]{1, 2};

    private static final byte[] BODY_WITHOUT_PADDING = new byte[]{65, 119};

    private static final byte[] EMPTY_BODY = new byte[]{};

    private static final byte[] LINE_FEED_BODY = new byte[]{10};

    private static final String FOOTER_LENGTH_BODY = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY";

    private static final int CHARACTER = 100;

    private static final int BUFFER_SIZE = 128;

    private static final int END_OF_FILE = -1;

    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final int LONG_LINE_LENGTH = 65;

    private static final int MAXIMUM_LINE_LENGTH = 64;

    private static final String PADDING_KEYWORD = "padding";

    @Test
    void testHeaderInvalid() throws IOException {
        final byte[] header = new byte[ArmoredIndicator.HEADER.getLength()];
        final ReadableByteChannel inputChannel = getInputChannel(header);

        assertThrows(ArmoredDecodingException.class, () -> new ArmoredReadableByteChannel(inputChannel));
    }

    @Test
    void testHeaderNotFound() throws IOException {
        final ReadableByteChannel inputChannel = getInputChannel(BODY_DECODED);

        assertThrows(ArmoredDecodingException.class, () -> new ArmoredReadableByteChannel(inputChannel));
    }

    @Test
    void testHeader() throws IOException {
        final ReadableByteChannel inputChannel = getHeaderFooterInputChannel(BODY.getBytes(CHARACTER_SET));

        try (ArmoredReadableByteChannel channel = new ArmoredReadableByteChannel(inputChannel)) {
            assertTrue(channel.isOpen());
            channel.close();
            assertFalse(channel.isOpen());
        }
    }

    @Test
    void testRead() throws IOException {
        final ReadableByteChannel inputChannel = getHeaderFooterInputChannel(BODY.getBytes(CHARACTER_SET));

        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        try (ArmoredReadableByteChannel channel = new ArmoredReadableByteChannel(inputChannel)) {
            assertReadSuccess(channel, buffer);
        }
    }

    @Test
    void testReadLineFeedBeforeHeader() throws IOException {
        final ByteArrayOutputStream outputStream = getHeaderFooter(BODY.getBytes());
        final byte[] armored = outputStream.toByteArray();

        final ByteArrayOutputStream lineFeedOutputStream = new ByteArrayOutputStream();
        lineFeedOutputStream.write(ArmoredSeparator.LINE_FEED.getCode());
        lineFeedOutputStream.write(armored);

        final ReadableByteChannel inputChannel = getChannel(lineFeedOutputStream);

        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        try (ArmoredReadableByteChannel channel = new ArmoredReadableByteChannel(inputChannel)) {
            assertReadSuccess(channel, buffer);
        }
    }

    @Test
    void testReadCharacterAfterFooter() throws IOException {
        final ByteArrayOutputStream outputStream = getHeaderFooter(BODY.getBytes());
        outputStream.write(CHARACTER);
        final ReadableByteChannel inputChannel = getChannel(outputStream);

        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        try (ArmoredReadableByteChannel channel = new ArmoredReadableByteChannel(inputChannel)) {
            assertTrue(channel.isOpen());

            final ArmoredDecodingException exception = assertThrows(ArmoredDecodingException.class, () -> channel.read(buffer));
            assertTrue(exception.getMessage().contains(Integer.toString(CHARACTER)));
        }
    }

    @Test
    void testReadLineFeedAfterFooter() throws IOException {
        final ByteArrayOutputStream outputStream = getHeaderFooter(BODY.getBytes());
        outputStream.write(ArmoredSeparator.LINE_FEED.getCode());
        final ReadableByteChannel inputChannel = getChannel(outputStream);

        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        try (ArmoredReadableByteChannel channel = new ArmoredReadableByteChannel(inputChannel)) {
            assertReadSuccess(channel, buffer);
        }
    }

    @Test
    void testReadEmptyLine() throws IOException {
        final ReadableByteChannel inputChannel = getHeaderFooterInputChannel(EMPTY_BODY);

        assertThrows(ArmoredDecodingException.class, () -> new ArmoredReadableByteChannel(inputChannel));
    }

    @Test
    void testReadLineLengthExceeded() throws IOException {
        final byte[] line = new byte[LONG_LINE_LENGTH];
        SECURE_RANDOM.nextBytes(line);
        final ReadableByteChannel inputChannel = getHeaderFooterInputChannel(line);

        final ArmoredDecodingException exception = assertThrows(ArmoredDecodingException.class, () -> new ArmoredReadableByteChannel(inputChannel));
        assertTrue(exception.getMessage().contains(Integer.toString(MAXIMUM_LINE_LENGTH)));
    }

    @Test
    void testReadPaddingNotFound() throws IOException {

        final ReadableByteChannel inputChannel = getHeaderFooterInputChannel(BODY_WITHOUT_PADDING);

        final ArmoredDecodingException exception = assertThrows(ArmoredDecodingException.class, () -> new ArmoredReadableByteChannel(inputChannel));
        assertTrue(exception.getMessage().contains(PADDING_KEYWORD));
    }

    @Test
    void testReadEncodingInvalid() throws IOException {
        final ReadableByteChannel inputChannel = getHeaderFooterInputChannel(BODY_INVALID);

        assertThrows(ArmoredDecodingException.class, () -> new ArmoredReadableByteChannel(inputChannel));
    }

    @Test
    void testReadHeaderEmptyLineBeforeFooter() throws IOException {
        final ReadableByteChannel inputChannel = getHeaderFooterInputChannel(LINE_FEED_BODY);

        assertThrows(ArmoredDecodingException.class, () -> new ArmoredReadableByteChannel(inputChannel));
    }

    @Test
    void testReadHeaderFooterLengthBody() throws IOException {
        final ReadableByteChannel inputChannel = getHeaderFooterInputChannel(FOOTER_LENGTH_BODY.getBytes(CHARACTER_SET));

        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        try (ArmoredReadableByteChannel channel = new ArmoredReadableByteChannel(inputChannel)) {
            assertTrue(channel.isOpen());

            final int read = channel.read(buffer);
            assertEquals(END_OF_FILE, read);
            buffer.flip();
            final byte[] decoded = new byte[buffer.remaining()];
            buffer.get(decoded);

            final byte[] expected = DECODER.decode(FOOTER_LENGTH_BODY);
            assertArrayEquals(expected, decoded);
        }
    }

    private void assertReadSuccess(final ReadableByteChannel channel, final ByteBuffer buffer) throws IOException {
        assertTrue(channel.isOpen());

        final int read = channel.read(buffer);
        assertEquals(END_OF_FILE, read);
        buffer.flip();

        final byte[] decoded = new byte[buffer.remaining()];
        buffer.get(decoded);
        assertArrayEquals(BODY_DECODED, decoded);
    }

    private ReadableByteChannel getInputChannel(final byte[] header) throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(header);
        outputStream.write(ArmoredSeparator.LINE_FEED.getCode());
        return getChannel(outputStream);
    }

    private ReadableByteChannel getHeaderFooterInputChannel(final byte[] body) throws IOException {
        final ByteArrayOutputStream outputStream = getHeaderFooter(body);
        return getChannel(outputStream);
    }

    private ByteArrayOutputStream getHeaderFooter(final byte[] body) throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(ArmoredIndicator.HEADER.getIndicator());
        outputStream.write(ArmoredSeparator.LINE_FEED.getCode());
        outputStream.write(body);
        outputStream.write(ArmoredSeparator.LINE_FEED.getCode());
        outputStream.write(ArmoredIndicator.FOOTER.getIndicator());
        outputStream.write(ArmoredSeparator.LINE_FEED.getCode());
        return outputStream;
    }

    private ReadableByteChannel getChannel(final ByteArrayOutputStream outputStream) {
        final byte[] bytes = outputStream.toByteArray();
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        return Channels.newChannel(inputStream);
    }
}
