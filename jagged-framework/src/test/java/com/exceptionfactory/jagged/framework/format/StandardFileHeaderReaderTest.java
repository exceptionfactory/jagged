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
package com.exceptionfactory.jagged.framework.format;

import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandardFileHeaderReaderTest {
    private static final String INVALID_VERSION = "age-encryption.org/v0";

    private static final String VERSION_WORD = "version";

    private static final byte CARRIAGE_RETURN = 13;

    private static final int DELETE = 127;

    private static final String RECIPIENT_TYPE = "type";

    private static final String ARGUMENT = "argument";

    private static final String SECOND_ARGUMENT = "second-argument";

    private static final String INVALID_CHARACTER_KEYWORD = "invalid character";

    private static final byte[] BODY = new byte[]{1, 1};

    private static final byte[] MESSAGE_AUTHENTICATION_CODE = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final CanonicalBase64.Encoder ENCODER = CanonicalBase64.getEncoder();

    private StandardFileHeaderReader reader;

    @BeforeEach
    void setReader() {
        reader = new StandardFileHeaderReader();
    }

    @Test
    void testGetFileHeaderVersionNotFound() {
        final byte[] version = new byte[SectionIndicator.VERSION.getLength()];
        final ByteBuffer buffer = ByteBuffer.wrap(version);

        assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
    }

    @Test
    void testGetFileHeaderSupportedVersionNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(INVALID_VERSION.getBytes(StandardCharsets.UTF_8));
        outputStream.write(CARRIAGE_RETURN);
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        final HeaderDecodingException exception = assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
        assertTrue(exception.getMessage().contains(VERSION_WORD));
    }

    @Test
    void testGetFileHeaderVersionLineFeedNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(SectionIndicator.VERSION.getIndicator());
        outputStream.write(CARRIAGE_RETURN);
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        final HeaderDecodingException exception = assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
        assertTrue(exception.getMessage().contains(Byte.toString(CARRIAGE_RETURN)));
    }

    @Test
    void testGetFileHeaderRecipientStanzasNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
    }

    @Test
    void testGetFileHeaderRecipientStanzaTypeLineFeedNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
    }

    @Test
    void testGetFileHeaderRecipientStanzaTypeArgumentsLineFeedNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.SPACE.getCode());
        outputStream.write(ARGUMENT.getBytes(StandardCharsets.UTF_8));
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
    }

    @Test
    void testGetFileHeaderRecipientStanzaArgumentsNotFound() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
        writeRecipientBody(outputStream);
        writeMessageAuthenticationCode(outputStream);
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        final FileHeader fileHeader = reader.getFileHeader(buffer);
        final Iterable<RecipientStanza> recipientStanzas = fileHeader.getRecipientStanzas();
        final Iterator<RecipientStanza> stanzas = recipientStanzas.iterator();
        assertTrue(stanzas.hasNext());

        final RecipientStanza recipientStanza = stanzas.next();
        assertEquals(RECIPIENT_TYPE, recipientStanza.getType());
        assertTrue(recipientStanza.getArguments().isEmpty());
        assertArrayEquals(BODY, recipientStanza.getBody());
        assertArrayEquals(MESSAGE_AUTHENTICATION_CODE, fileHeader.getMessageAuthenticationCode());
    }

    @Test
    void testGetFileHeaderRecipientArgumentsDeleteCharacterFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.SPACE.getCode());
        outputStream.write(DELETE);
        outputStream.write(SectionSeparator.LINE_FEED.getCode());

        final ByteBuffer buffer = ByteBuffer.wrap(outputStream.toByteArray());

        final HeaderDecodingException exception = assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
        assertTrue(exception.getMessage().contains(INVALID_CHARACTER_KEYWORD));
    }

    @Test
    void testGetFileHeaderRecipientArgumentsCarriageReturnCharacterFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.SPACE.getCode());
        outputStream.write(CARRIAGE_RETURN);
        outputStream.write(SectionSeparator.LINE_FEED.getCode());

        final ByteBuffer buffer = ByteBuffer.wrap(outputStream.toByteArray());

        final HeaderDecodingException exception = assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
        assertTrue(exception.getMessage().contains(INVALID_CHARACTER_KEYWORD));
    }


    @Test
    void testGetFileHeaderRecipientStanzaEndHeaderNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        writeRecipientTypeArgument(outputStream);
        writeRecipientBody(outputStream);
        writeVersion(outputStream);
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
    }

    @Test
    void testGetFileHeaderRecipientStanzaBodyNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        writeRecipientTypeArgument(outputStream);
        writeMessageAuthenticationCode(outputStream);
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        final HeaderDecodingException exception = assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
        assertInstanceOf(IllegalArgumentException.class, exception.getCause());
    }

    @Test
    void testGetFileHeaderMessageAuthenticationCodeNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
        writeRecipientBody(outputStream);
        outputStream.write(SectionIndicator.END.getIndicator());
        outputStream.write(SectionSeparator.SPACE.getCode());
        final ByteBuffer buffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
    }

    @Test
    void testGetFileHeaderMessageAuthenticationCodeLineFeedNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
        writeRecipientBody(outputStream);
        outputStream.write(SectionIndicator.END.getIndicator());
        outputStream.write(SectionSeparator.SPACE.getCode());
        final byte[] encoded = ENCODER.encode(MESSAGE_AUTHENTICATION_CODE);
        outputStream.write(encoded);
        outputStream.write(SectionSeparator.SPACE.getCode());
        final ByteBuffer buffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
    }

    @Test
    void testGetFileHeaderEndSpaceSeparatorNotFound() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
        writeRecipientBody(outputStream);
        outputStream.write(SectionIndicator.END.getIndicator());
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
        final ByteBuffer buffer = ByteBuffer.wrap(outputStream.toByteArray());

        assertThrows(HeaderDecodingException.class, () -> reader.getFileHeader(buffer));
    }

    @Test
    void testGetFileHeader() throws GeneralSecurityException, IOException {
        final ByteBuffer buffer = getFileHeaderBuffer();

        final FileHeader fileHeader = reader.getFileHeader(buffer);
        final Iterable<RecipientStanza> recipientStanzas = fileHeader.getRecipientStanzas();
        final Iterator<RecipientStanza> stanzas = recipientStanzas.iterator();
        assertTrue(stanzas.hasNext());

        final RecipientStanza recipientStanza = stanzas.next();
        assertEquals(RECIPIENT_TYPE, recipientStanza.getType());

        final Iterator<String> arguments = recipientStanza.getArguments().iterator();
        assertTrue(arguments.hasNext());
        final String argument = arguments.next();
        assertEquals(ARGUMENT, argument);
        assertTrue(arguments.hasNext());
        final String secondArgument = arguments.next();
        assertEquals(SECOND_ARGUMENT, secondArgument);
        assertFalse(arguments.hasNext());

        assertArrayEquals(BODY, recipientStanza.getBody());
        assertArrayEquals(MESSAGE_AUTHENTICATION_CODE, fileHeader.getMessageAuthenticationCode());
    }

    protected static ByteBuffer getFileHeaderBuffer() throws IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        writeRecipientTypeArguments(outputStream);
        writeRecipientBody(outputStream);
        writeMessageAuthenticationCode(outputStream);
        final byte[] bytes = outputStream.toByteArray();
        return ByteBuffer.wrap(bytes);
    }

    private static void writeVersion(final OutputStream outputStream) throws IOException {
        outputStream.write(SectionIndicator.VERSION.getIndicator());
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private static void writeRecipientTypeArgument(final OutputStream outputStream) throws IOException {
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.SPACE.getCode());
        outputStream.write(ARGUMENT.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private static void writeRecipientTypeArguments(final OutputStream outputStream) throws IOException {
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.SPACE.getCode());
        outputStream.write(ARGUMENT.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.SPACE.getCode());
        outputStream.write(SECOND_ARGUMENT.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private static void writeRecipientBody(final OutputStream outputStream) throws IOException {
        outputStream.write(ENCODER.encode(BODY));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private static void writeMessageAuthenticationCode(final OutputStream outputStream) throws IOException {
        outputStream.write(SectionIndicator.END.getIndicator());
        outputStream.write(SectionSeparator.SPACE.getCode());
        final byte[] encoded = ENCODER.encode(MESSAGE_AUTHENTICATION_CODE);
        outputStream.write(encoded);
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }
}
