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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArmoredWritableByteChannelTest {
    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    private static final byte[] EMPTY = new byte[]{};

    private static final byte[] SHORT_LINE = new byte[]{1, 2, 3, 4};

    private static final byte[] SHORT_LINE_EXPECTED = ENCODER.encode(SHORT_LINE);

    private static final byte[] QUARTER_LINE = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2
    };

    private static final byte[] QUARTER_LINE_EXPECTED = ENCODER.encode(QUARTER_LINE);

    private static final byte[] LINE = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final byte[] LINE_EXPECTED = ENCODER.encode(LINE);

    private static final int THREE_LINE_LENGTH = 192;

    @Test
    void testWriteEmptyClose() throws IOException {
        assertArmoredEquals(EMPTY, EMPTY);
    }

    @Test
    void testWriteShortLineClose() throws IOException {
        assertArmoredEquals(SHORT_LINE_EXPECTED, SHORT_LINE);
    }

    @Test
    void testWriteLineClose() throws IOException {
        assertArmoredEquals(LINE_EXPECTED, LINE);
    }

    @Test
    void testWriteLineAndShortLine() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final ArmoredWritableByteChannel channel = new ArmoredWritableByteChannel(outputChannel);
        channel.write(ByteBuffer.wrap(LINE));
        channel.write(ByteBuffer.wrap(SHORT_LINE));
        channel.close();

        final byte[] armored = outputStream.toByteArray();
        final byte[] expected = getExpected(LINE_EXPECTED, SHORT_LINE_EXPECTED);
        assertArrayEquals(expected, armored);
    }

    @Test
    void testWriteLines() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final ArmoredWritableByteChannel channel = new ArmoredWritableByteChannel(outputChannel);
        final ByteBuffer buffer = ByteBuffer.allocate(THREE_LINE_LENGTH);
        buffer.put(LINE);
        buffer.put(LINE);
        buffer.put(LINE);
        buffer.flip();

        channel.write(buffer);
        channel.close();

        final byte[] armored = outputStream.toByteArray();
        final byte[] expected = getExpected(LINE_EXPECTED, LINE_EXPECTED, LINE_EXPECTED);
        assertArrayEquals(expected, armored);
    }

    @Test
    void testWriteFiveQuarterLines() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final ArmoredWritableByteChannel channel = new ArmoredWritableByteChannel(outputChannel);
        final ByteBuffer quarterLineBuffer = ByteBuffer.wrap(QUARTER_LINE);
        channel.write(quarterLineBuffer);
        quarterLineBuffer.flip();
        channel.write(quarterLineBuffer);
        quarterLineBuffer.flip();
        channel.write(quarterLineBuffer);
        quarterLineBuffer.flip();
        channel.write(quarterLineBuffer);
        quarterLineBuffer.flip();
        channel.write(quarterLineBuffer);

        channel.close();

        final byte[] armored = outputStream.toByteArray();

        final ByteBuffer combinedLines = ByteBuffer.allocate(LINE.length);
        combinedLines.put(QUARTER_LINE);
        combinedLines.put(QUARTER_LINE);
        combinedLines.put(QUARTER_LINE);
        combinedLines.put(QUARTER_LINE);
        combinedLines.flip();
        final ByteBuffer encodedBuffer = ENCODER.encode(combinedLines);
        final byte[] lineExpected = encodedBuffer.array();

        final byte[] expected = getExpected(lineExpected, QUARTER_LINE_EXPECTED);
        assertArrayEquals(expected, armored);
    }

    private void assertArmoredEquals(final byte[] expectedBody, final byte[] sourceBody) throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final ArmoredWritableByteChannel channel = new ArmoredWritableByteChannel(outputChannel);
        assertTrue(channel.isOpen());

        final ByteBuffer buffer = ByteBuffer.wrap(sourceBody);
        final int written = channel.write(buffer);
        assertEquals(sourceBody.length, written);

        channel.close();
        assertFalse(channel.isOpen());

        final byte[] armored = outputStream.toByteArray();
        final byte[] expected = getExpected(expectedBody);
        assertArrayEquals(expected, armored);
    }

    private byte[] getExpected(final byte[]... lines) throws IOException {
        final ByteArrayOutputStream expectedStream = new ByteArrayOutputStream();
        expectedStream.write(ArmoredIndicator.HEADER.getIndicator());
        expectedStream.write(ArmoredSeparator.LINE_FEED.getCode());
        for (final byte[] line : lines) {
            expectedStream.write(line);
            if (line.length > 0) {
                expectedStream.write(ArmoredSeparator.LINE_FEED.getCode());
            }
        }
        expectedStream.write(ArmoredIndicator.FOOTER.getIndicator());
        expectedStream.write(ArmoredSeparator.LINE_FEED.getCode());
        return expectedStream.toByteArray();
    }
}
