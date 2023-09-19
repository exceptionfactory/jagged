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
import com.exceptionfactory.jagged.framework.crypto.ByteBufferCipherFactory;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.StandardByteBufferCipherFactory;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EncryptingChannelTest {
    private static final int EMPTY_ENCRYPTED_LENGTH = 16;

    private static final byte[] INVALID_KEY = new byte[]{};

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
        final EncryptingChannel encryptingChannel = getEncryptingChannel(outputStream);

        assertTrue(encryptingChannel.isOpen());
    }

    @Test
    void testClose() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final EncryptingChannel encryptingChannel = getEncryptingChannel(outputStream);

        assertTrue(encryptingChannel.isOpen());
        encryptingChannel.close();
        assertFalse(encryptingChannel.isOpen());
    }

    @Test
    void testEmpty() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final EncryptingChannel encryptingChannel = getEncryptingChannel(outputStream);

        assertTrue(encryptingChannel.isOpen());
        encryptingChannel.close();

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(EMPTY_ENCRYPTED_LENGTH, bytes.length);
    }

    @Test
    void testWritePayloadException() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);

        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);

        final CipherKey payloadKey = mock(CipherKey.class);
        lenient().when(payloadKey.getEncoded()).thenReturn(INVALID_KEY);
        when(payloadKeyWriter.writeFileHeader(any(), any())).thenReturn(payloadKey);

        final ByteBufferCipherFactory byteBufferCipherFactory = new StandardByteBufferCipherFactory();
        final EncryptingChannel encryptingChannel = new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter, byteBufferCipherFactory);

        final ByteBuffer sourceBuffer = ByteBuffer.wrap(SOURCE);
        final int written = encryptingChannel.write(sourceBuffer);
        assertEquals(sourceBuffer.capacity(), written);

        assertThrows(PayloadException.class, encryptingChannel::close);
    }

    @Test
    void testWrite() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final EncryptingChannel encryptingChannel = getEncryptingChannel(outputStream);

        final ByteBuffer sourceBuffer = ByteBuffer.wrap(SOURCE);
        final int written = encryptingChannel.write(sourceBuffer);
        assertEquals(sourceBuffer.capacity(), written);

        encryptingChannel.close();

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(SOURCE_ENCRYPTED_LENGTH, bytes.length);
    }

    @Test
    void testWriteSingleChunk() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final EncryptingChannel encryptingChannel = getEncryptingChannel(outputStream);

        final byte[] chunk = new byte[ChunkSize.PLAIN.getSize()];
        final ByteBuffer sourceBuffer = ByteBuffer.wrap(chunk);
        final int written = encryptingChannel.write(sourceBuffer);
        assertEquals(sourceBuffer.capacity(), written);

        encryptingChannel.close();

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(ChunkSize.ENCRYPTED.getSize(), bytes.length);
    }

    @Test
    void testWriteMultipleChunks() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final EncryptingChannel encryptingChannel = getEncryptingChannel(outputStream);

        final byte[] chunks = new byte[TWO_CHUNKS_LENGTH];
        final ByteBuffer sourceBuffer = ByteBuffer.wrap(chunks);
        final int written = encryptingChannel.write(sourceBuffer);
        assertEquals(sourceBuffer.capacity(), written);

        encryptingChannel.close();

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(TWO_CHUNKS_ENCRYPTED_LENGTH, bytes.length);
    }

    @Test
    void testWriteMultipleChunksBufferSingleChunk() throws GeneralSecurityException, IOException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final EncryptingChannel encryptingChannel = getEncryptingChannel(outputStream);

        final byte[] chunks = new byte[TWO_CHUNKS_LENGTH];
        final ByteBuffer sourceBuffer = ByteBuffer.wrap(chunks);
        sourceBuffer.position(ChunkSize.PLAIN.getSize());
        final int sourceBufferRemaining = sourceBuffer.remaining();

        final int written = encryptingChannel.write(sourceBuffer);
        assertEquals(sourceBufferRemaining, written);

        encryptingChannel.close();

        final byte[] bytes = outputStream.toByteArray();
        assertEquals(ChunkSize.ENCRYPTED.getSize(), bytes.length);
    }

    private EncryptingChannel getEncryptingChannel(final ByteArrayOutputStream outputStream) throws GeneralSecurityException, IOException {
        final WritableByteChannel outputChannel = Channels.newChannel(outputStream);
        final List<RecipientStanzaWriter> recipientStanzaWriters = Collections.singletonList(recipientStanzaWriter);
        when(payloadKeyWriter.writeFileHeader(any(), any())).thenReturn(PAYLOAD_KEY);
        final ByteBufferCipherFactory byteBufferCipherFactory = new StandardByteBufferCipherFactory();
        return new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter, byteBufferCipherFactory);
    }
}
