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
package com.exceptionfactory.jagged.framework.stream;

import com.exceptionfactory.jagged.PayloadException;
import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.crypto.ChunkSize;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.format.PayloadKeyWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EncryptingChannelTest {
    private static final int EMPTY_ENCRYPTED_LENGTH = 0;

    private static final byte[] SYMMETRIC_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final CipherKey PAYLOAD_KEY = new CipherKey(SYMMETRIC_KEY);

    private static final byte[] SOURCE = String.class.getSimpleName().getBytes(StandardCharsets.UTF_8);

    private static final int SOURCE_ENCRYPTED_LENGTH = 22;

    private static final int TWO_CHUNKS_LENGTH = 131072;

    private static final int TWO_CHUNKS_ENCRYPTED_LENGTH = 131104;

    @Mock
    private PayloadKeyWriter payloadKeyWriter;

    @Mock
    private RecipientStanzaWriter recipientStanzaWriter;

    @Test
    void testIsOpen() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);
        final EncryptingChannel encryptingChannel = new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter);

        assertTrue(encryptingChannel.isOpen());
    }

    @Test
    void testClose() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);
        when(payloadKeyWriter.writeFileHeader(any(), any())).thenReturn(PAYLOAD_KEY);
        final EncryptingChannel encryptingChannel = new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter);

        assertTrue(encryptingChannel.isOpen());
        encryptingChannel.close();
        assertFalse(encryptingChannel.isOpen());

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(EMPTY_ENCRYPTED_LENGTH, bytes.length);
    }

    @Test
    void testWritePayloadException() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);

        final CipherKey payloadKey = mock(CipherKey.class);
        when(payloadKeyWriter.writeFileHeader(any(), any())).thenReturn(payloadKey);
        final EncryptingChannel encryptingChannel = new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter);

        final ByteBuffer sourceBuffer = ByteBuffer.wrap(SOURCE);
        encryptingChannel.write(sourceBuffer);

        assertThrows(PayloadException.class, encryptingChannel::close);
    }

    @Test
    void testWrite() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);
        when(payloadKeyWriter.writeFileHeader(any(), any())).thenReturn(PAYLOAD_KEY);
        final EncryptingChannel encryptingChannel = new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter);

        final ByteBuffer sourceBuffer = ByteBuffer.wrap(SOURCE);
        encryptingChannel.write(sourceBuffer);

        encryptingChannel.close();

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(SOURCE_ENCRYPTED_LENGTH, bytes.length);
    }

    @Test
    void testWriteSingleChunk() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);
        when(payloadKeyWriter.writeFileHeader(any(), any())).thenReturn(PAYLOAD_KEY);
        final EncryptingChannel encryptingChannel = new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter);

        final byte[] chunk = new byte[ChunkSize.PLAIN.getSize()];
        final ByteBuffer sourceBuffer = ByteBuffer.wrap(chunk);
        encryptingChannel.write(sourceBuffer);

        encryptingChannel.close();

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(ChunkSize.ENCRYPTED.getSize(), bytes.length);
    }

    @Test
    void testWriteMultipleChunks() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);
        when(payloadKeyWriter.writeFileHeader(any(), any())).thenReturn(PAYLOAD_KEY);
        final EncryptingChannel encryptingChannel = new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter);

        final byte[] chunks = new byte[TWO_CHUNKS_LENGTH];
        final ByteBuffer sourceBuffer = ByteBuffer.wrap(chunks);
        encryptingChannel.write(sourceBuffer);

        encryptingChannel.close();

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(TWO_CHUNKS_ENCRYPTED_LENGTH, bytes.length);
    }
}
