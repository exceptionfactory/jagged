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
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.framework.crypto.ByteBufferCipherOperationFactory;
import com.exceptionfactory.jagged.framework.crypto.ByteBufferEncryptor;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.format.PayloadKeyReader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DecryptingChannelTest {
    private static final byte[] INPUT = String.class.getSimpleName().getBytes(StandardCharsets.UTF_8);

    private static final int HALF_BUFFER_SIZE = 128;

    private static final int BUFFER_SIZE = 256;

    private static final int ENCRYPTED_BUFFER_SIZE = 272;

    private static final byte[] SYMMETRIC_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final byte[] LAST_CHUNK_INITIALIZATION_VECTOR = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    private static final byte[] SECOND_CHUNK_INITIALIZATION_VECTOR = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1};

    private static final int INCREMENTED_INDEX = 10;

    private static final int LAST_INDEX = 11;

    private static final int COUNTER = 1;

    private static final int END_OF_FILE = -1;

    private static final int ENCRYPTED_EMPTY_CHUNK_SIZE = 65568;

    private static final int TWO_CHUNKS_PLAIN_LENGTH = 131072;

    private static final int TWO_CHUNKS_ENCRYPTED_LENGTH = 131104;

    private static final CipherKey CIPHER_KEY = new CipherKey(SYMMETRIC_KEY);

    @Mock
    private RecipientStanzaReader recipientStanzaReader;

    @Mock
    private PayloadKeyReader payloadKeyReader;

    private Iterable<RecipientStanzaReader> recipientStanzaReaders;

    @BeforeEach
    void setReaders() {
        recipientStanzaReaders = Collections.singletonList(recipientStanzaReader);
    }

    @Test
    void testIsOpen() throws IOException, GeneralSecurityException {
        final ReadableByteChannel inputChannel = getInputChannel();

        final DecryptingChannel decryptingChannel = new DecryptingChannel(inputChannel, recipientStanzaReaders, payloadKeyReader);

        assertTrue(decryptingChannel.isOpen());
    }

    @Test
    void testClose() throws IOException, GeneralSecurityException {
        final ReadableByteChannel inputChannel = getInputChannel();

        when(payloadKeyReader.getPayloadKey(any(), any())).thenReturn(CIPHER_KEY);
        final DecryptingChannel decryptingChannel = new DecryptingChannel(inputChannel, recipientStanzaReaders, payloadKeyReader);

        decryptingChannel.close();
        assertFalse(inputChannel.isOpen());
    }

    @Test
    void testConstructorPayloadNotFound() {
        final ReadableByteChannel inputChannel = getInputChannel();

        assertThrows(PayloadException.class, () -> new DecryptingChannel(inputChannel, recipientStanzaReaders, new GetRemainingBufferPayloadKeyReader()));
    }

    @Test
    void testConstructorEncryptedChunkSize() throws GeneralSecurityException, IOException {
        final byte[] chunkBytes = new byte[ChunkSize.ENCRYPTED.getSize()];
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(chunkBytes);
        final ReadableByteChannel inputChannel = Channels.newChannel(inputStream);

        final DecryptingChannel decryptingChannel = new DecryptingChannel(inputChannel, recipientStanzaReaders, payloadKeyReader);

        assertTrue(decryptingChannel.isOpen());
    }

    @Test
    void testReadPayloadException() throws GeneralSecurityException, IOException {
        final byte[] chunkBytes = new byte[BUFFER_SIZE];
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(chunkBytes);
        final ReadableByteChannel inputChannel = Channels.newChannel(inputStream);

        when(payloadKeyReader.getPayloadKey(any(), any())).thenReturn(CIPHER_KEY);
        final DecryptingChannel decryptingChannel = new DecryptingChannel(inputChannel, recipientStanzaReaders, payloadKeyReader);

        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        assertThrows(PayloadException.class, () -> decryptingChannel.read(buffer));
    }

    @Test
    void testReadLastChunkNotFound() throws GeneralSecurityException, IOException {
        when(payloadKeyReader.getPayloadKey(any(), any())).thenReturn(CIPHER_KEY);

        final byte[] firstInitializationVector = new byte[LAST_CHUNK_INITIALIZATION_VECTOR.length];
        final IvParameterSpec firstParameterSpec = new IvParameterSpec(firstInitializationVector);
        final ByteBufferEncryptor encryptor = ByteBufferCipherOperationFactory.newByteBufferEncryptor(CIPHER_KEY, firstParameterSpec);

        final byte[] inputBytes = new byte[ChunkSize.PLAIN.getSize()];
        final ByteBuffer inputBuffer = ByteBuffer.wrap(inputBytes);
        final ByteBuffer encryptedBuffer = ByteBuffer.allocate(ENCRYPTED_EMPTY_CHUNK_SIZE);
        encryptor.encrypt(inputBuffer, encryptedBuffer);

        final byte[] lastInitializationVector = new byte[LAST_CHUNK_INITIALIZATION_VECTOR.length];
        lastInitializationVector[INCREMENTED_INDEX] = COUNTER;
        lastInitializationVector[LAST_INDEX] = COUNTER;

        final IvParameterSpec lastParameterSpec = new IvParameterSpec(lastInitializationVector);
        final ByteBufferEncryptor lastEncryptor = ByteBufferCipherOperationFactory.newByteBufferEncryptor(CIPHER_KEY, lastParameterSpec);
        final ByteBuffer emptyInputBuffer = ByteBuffer.allocate(0);
        lastEncryptor.encrypt(emptyInputBuffer, encryptedBuffer);

        final byte[] encryptedBytes = encryptedBuffer.array();
        final ReadableByteChannel encryptedChannel = Channels.newChannel(new ByteArrayInputStream(encryptedBytes));

        final DecryptingChannel decryptingChannel = new DecryptingChannel(encryptedChannel, recipientStanzaReaders, payloadKeyReader);
        final ByteBuffer outputBuffer = ByteBuffer.allocate(ChunkSize.ENCRYPTED.getSize());

        final PayloadException exception = assertThrows(PayloadException.class, () -> decryptingChannel.read(outputBuffer));
        assertInstanceOf(IllegalBlockSizeException.class, exception.getCause());
    }

    @Test
    void testRead() throws GeneralSecurityException, IOException {
        when(payloadKeyReader.getPayloadKey(any(), any())).thenReturn(CIPHER_KEY);

        final IvParameterSpec parameterSpec = new IvParameterSpec(LAST_CHUNK_INITIALIZATION_VECTOR);
        final ByteBufferEncryptor encryptor = ByteBufferCipherOperationFactory.newByteBufferEncryptor(CIPHER_KEY, parameterSpec);
        final byte[] inputBytes = new byte[BUFFER_SIZE];
        final ByteBuffer inputBuffer = ByteBuffer.wrap(inputBytes);
        final ByteBuffer encryptedBuffer = ByteBuffer.allocate(ENCRYPTED_BUFFER_SIZE);
        encryptor.encrypt(inputBuffer, encryptedBuffer);

        final byte[] encryptedBytes = encryptedBuffer.array();
        final ReadableByteChannel encryptedChannel = Channels.newChannel(new ByteArrayInputStream(encryptedBytes));

        final DecryptingChannel decryptingChannel = new DecryptingChannel(encryptedChannel, recipientStanzaReaders, payloadKeyReader);

        final ByteBuffer outputBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        outputBuffer.position(HALF_BUFFER_SIZE);
        final int firstDecrypted = decryptingChannel.read(outputBuffer);
        assertEquals(HALF_BUFFER_SIZE, firstDecrypted);

        outputBuffer.position(0);
        final int secondDecrypted = decryptingChannel.read(outputBuffer);
        assertEquals(END_OF_FILE, secondDecrypted);

        assertArrayEquals(inputBytes, outputBuffer.array());
    }

    @Test
    void testReadMultipleChunks() throws GeneralSecurityException, IOException {
        when(payloadKeyReader.getPayloadKey(any(), any())).thenReturn(CIPHER_KEY);

        final ByteBuffer encryptedBuffer = ByteBuffer.allocate(TWO_CHUNKS_ENCRYPTED_LENGTH);

        final IvParameterSpec firstChunkParameterSpec = new IvParameterSpec(new byte[LAST_CHUNK_INITIALIZATION_VECTOR.length]);
        final ByteBufferEncryptor firstChunkEncryptor = ByteBufferCipherOperationFactory.newByteBufferEncryptor(CIPHER_KEY, firstChunkParameterSpec);
        final byte[] chunk = new byte[ChunkSize.PLAIN.getSize()];
        final ByteBuffer chunkBuffer = ByteBuffer.wrap(chunk);
        firstChunkEncryptor.encrypt(chunkBuffer, encryptedBuffer);
        chunkBuffer.clear();

        final IvParameterSpec lastChunkParameterSpec = new IvParameterSpec(SECOND_CHUNK_INITIALIZATION_VECTOR);
        final ByteBufferEncryptor lastChunkEncryptor = ByteBufferCipherOperationFactory.newByteBufferEncryptor(CIPHER_KEY, lastChunkParameterSpec);
        lastChunkEncryptor.encrypt(chunkBuffer, encryptedBuffer);

        final byte[] encryptedBytes = encryptedBuffer.array();
        final ReadableByteChannel encryptedChannel = Channels.newChannel(new ByteArrayInputStream(encryptedBytes));
        final DecryptingChannel decryptingChannel = new DecryptingChannel(encryptedChannel, recipientStanzaReaders, payloadKeyReader);

        final ByteBuffer outputBuffer = ByteBuffer.allocate(TWO_CHUNKS_PLAIN_LENGTH);
        final int decrypted = decryptingChannel.read(outputBuffer);

        assertEquals(outputBuffer.limit(), decrypted);
        final byte[] chunksExpected = new byte[TWO_CHUNKS_PLAIN_LENGTH];
        assertArrayEquals(chunksExpected, outputBuffer.array());

        outputBuffer.clear();
        final int read = decryptingChannel.read(outputBuffer);
        assertEquals(END_OF_FILE, read);
    }

    private ReadableByteChannel getInputChannel() {
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(INPUT);
        return Channels.newChannel(inputStream);
    }

    private static class GetRemainingBufferPayloadKeyReader implements PayloadKeyReader {

        @Override
        public CipherKey getPayloadKey(final ByteBuffer buffer, final Iterable<RecipientStanzaReader> recipientStanzaReaders) {
            final int remaining = buffer.remaining();
            final byte[] bytes = new byte[remaining];
            buffer.get(bytes);
            return null;
        }
    }
}
