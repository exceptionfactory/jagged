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
import com.exceptionfactory.jagged.framework.crypto.ByteBufferCipherFactory;
import com.exceptionfactory.jagged.framework.crypto.ByteBufferDecryptor;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.PayloadIvParameterSpec;
import com.exceptionfactory.jagged.framework.format.PayloadKeyReader;

import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Decrypting implementation of Readable Byte Channel capable of streaming decryption in chunks of 64 KiB
 */
class DecryptingChannel implements ReadableByteChannel {
    private static final int END_OF_FILE = -1;

    private final ByteBuffer inputBuffer = ByteBuffer.allocate(ChunkSize.ENCRYPTED.getSize());

    private final ByteBuffer nextByteInputBuffer = ByteBuffer.allocate(1);

    private final ByteBuffer plainBuffer = ByteBuffer.allocate(ChunkSize.PLAIN.getSize());

    private final PayloadIvParameterSpec payloadIvParameterSpec = new PayloadIvParameterSpec();

    private final ReadableByteChannel inputChannel;

    private final CipherKey payloadKey;

    private final ByteBufferCipherFactory byteBufferCipherFactory;

    /**
     * Decrypting Channel constructor reads the File Header from the encrypted input Channel using the Recipient Stanza Reader
     *
     * @param inputChannel Input Channel containing encrypted age binary
     * @param recipientStanzaReaders Recipient Stanza Readers required to read File Key
     * @param payloadKeyReader Payload Key Reader
     * @param byteBufferCipherFactory Byte Buffer Cipher Factory for performing encryption operations
     * @throws IOException Thrown on failures to read initial encrypted payload after processing File Header
     * @throws GeneralSecurityException Thrown on failures to read File Key or construct Payload Key with supplied Recipient Stanza Reader
     */
    DecryptingChannel(
            final ReadableByteChannel inputChannel,
            final Iterable<RecipientStanzaReader> recipientStanzaReaders,
            final PayloadKeyReader payloadKeyReader,
            final ByteBufferCipherFactory byteBufferCipherFactory
    ) throws IOException, GeneralSecurityException {
        this.inputChannel = Objects.requireNonNull(inputChannel, "Input Channel required");
        this.byteBufferCipherFactory = Objects.requireNonNull(byteBufferCipherFactory, "Byte Buffer Cipher Factory required");
        readInputChannel();
        payloadKey = payloadKeyReader.getPayloadKey(inputBuffer, recipientStanzaReaders);

        if (inputBuffer.limit() == ChunkSize.ENCRYPTED.getSize()) {
            inputBuffer.compact();
            readInputChannel();
        } else if (inputBuffer.position() == inputBuffer.limit()) {
            throw new PayloadException(String.format("Payload not found after reading File Header [%d bytes]", inputBuffer.position()));
        }
        plainBuffer.flip();
    }

    /**
     * Read from decrypted buffer into provided output buffer and return bytes read
     *
     * @param outputBuffer Output Buffer into which decrypted bytes should be transferred
     * @return Bytes read from decrypted buffer and transferred to output buffer or end-of-stream indicator
     * @throws IOException Thrown on failures to read from encrypted input channel or decryption failures
     */
    @Override
    public int read(final ByteBuffer outputBuffer) throws IOException {
        Objects.requireNonNull(outputBuffer, "Output Buffer required");

        int read = 0;

        while (outputBuffer.hasRemaining()) {
            if (plainBuffer.remaining() == 0) {
                try {
                    readChunk();
                    inputBuffer.clear();
                    readInputChannel();
                } catch (final GeneralSecurityException e) {
                    final String message = String.format("Read chunk failed: counter %s", Arrays.toString(payloadIvParameterSpec.getIV()));
                    throw new PayloadException(message, e);
                }
            }

            final int plainBufferRead = readPlainBuffer(outputBuffer);
            if (END_OF_FILE == plainBufferRead) {
                read = END_OF_FILE;
                break;
            } else {
                read += plainBufferRead;
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
     * Clear buffers and close input channel
     *
     * @throws IOException Thrown on failures to close input channel
     */
    @Override
    public void close() throws IOException {
        payloadKey.destroy();
        plainBuffer.clear();
        inputBuffer.clear();
        nextByteInputBuffer.clear();
        inputChannel.close();
    }

    private void readInputChannel() throws IOException {
        if (inputBuffer.hasRemaining()) {
            nextByteInputBuffer.flip();
            inputBuffer.put(nextByteInputBuffer);
            nextByteInputBuffer.clear();
        }
        if (inputBuffer.hasRemaining()) {
            readInputChannel(inputBuffer);
            readInputChannel(nextByteInputBuffer);
        }
        inputBuffer.flip();
    }

    private void readInputChannel(final ByteBuffer buffer) throws IOException {
        int read = inputChannel.read(buffer);
        while (buffer.hasRemaining()) {
            if (END_OF_FILE == read) {
                payloadIvParameterSpec.setLastChunkFlag();
                break;
            }
            read = inputChannel.read(buffer);
        }
    }

    private int readPlainBuffer(final ByteBuffer outputBuffer) {
        int read = END_OF_FILE;
        if (plainBuffer.hasRemaining()) {
            read++;
        }

        final int plainBufferLimit = plainBuffer.limit();

        while (plainBuffer.hasRemaining()) {
            if (outputBuffer.hasRemaining()) {
                final int outputBufferRemaining = outputBuffer.remaining();
                final int plainBufferRemaining = plainBuffer.remaining();
                if (plainBufferRemaining > outputBufferRemaining) {
                    final int plainBufferInputLimit = plainBuffer.position() + outputBufferRemaining;
                    plainBuffer.limit(plainBufferInputLimit);
                }

                final int plainBufferStartPosition = plainBuffer.position();

                outputBuffer.put(plainBuffer);
                plainBuffer.limit(plainBufferLimit);

                final int plainBufferRead = plainBuffer.position() - plainBufferStartPosition;
                read += plainBufferRead;
            } else {
                break;
            }
        }
        return read;
    }

    /**
     * Read encrypted chunk from input buffer and write decrypted bytes to plain buffer
     *
     * @throws GeneralSecurityException Thrown on cipher configuration or decryption failures
     */
    private void readChunk() throws GeneralSecurityException {
        if (inputBuffer.hasRemaining()) {
            plainBuffer.clear();

            final ByteBufferDecryptor byteBufferDecryptor = byteBufferCipherFactory.newByteBufferDecryptor(payloadKey, payloadIvParameterSpec);
            byteBufferDecryptor.decrypt(inputBuffer, plainBuffer);

            if (plainBuffer.position() == 0 && payloadIvParameterSpec.isNotFirstChunk()) {
                throw new IllegalBlockSizeException("Last Payload chunk not found");
            }

            payloadIvParameterSpec.incrementInitializationVector();
            plainBuffer.flip();
        }
    }
}
