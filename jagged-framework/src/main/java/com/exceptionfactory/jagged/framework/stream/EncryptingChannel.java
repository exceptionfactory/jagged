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
import com.exceptionfactory.jagged.framework.crypto.ByteBufferCipherOperationFactory;
import com.exceptionfactory.jagged.framework.crypto.ByteBufferEncryptor;
import com.exceptionfactory.jagged.framework.crypto.ChunkSize;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.PayloadIvParameterSpec;
import com.exceptionfactory.jagged.framework.format.PayloadKeyWriter;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Encrypting implementation of Writable Byte Channel capable of streaming encryption in chunks of 64 KiB
 */
class EncryptingChannel implements WritableByteChannel {
    private final ByteBuffer inputBuffer = ByteBuffer.allocate(ChunkSize.PLAIN.getSize());

    private final ByteBuffer outputBuffer = ByteBuffer.allocate(ChunkSize.ENCRYPTED.getSize());

    private final PayloadIvParameterSpec payloadIvParameterSpec = new PayloadIvParameterSpec();

    private final WritableByteChannel outputChannel;

    private final CipherKey payloadKey;

    /**
     * Encrypting Channel constructor writes the File Header using Recipient Stanzas Writers then derives the Payload Key
     *
     * @param outputChannel Output Channel for encrypted header and payload
     * @param recipientStanzaWriters Recipient Stanza Writers for encrypting the File Key
     * @param payloadKeyWriter Payload Key Writer for serializing File Header and deriving Payload Key
     * @throws GeneralSecurityException Thrown on Payload Key derivation or Recipient Stanza processing failures
     * @throws IOException Thrown on failures serializing to Output Channel
     */
    EncryptingChannel(
            final WritableByteChannel outputChannel,
            final Iterable<RecipientStanzaWriter> recipientStanzaWriters,
            final PayloadKeyWriter payloadKeyWriter
    ) throws GeneralSecurityException, IOException {
        this.outputChannel = Objects.requireNonNull(outputChannel, "Output Channel required");
        Objects.requireNonNull(recipientStanzaWriters, "Recipient Stanza Writers required");
        Objects.requireNonNull(payloadKeyWriter, "Payload Key Writer required");

        this.payloadKey = payloadKeyWriter.writeFileHeader(outputBuffer, recipientStanzaWriters);
        flushOutputBuffer();
    }

    /**
     * Encrypt provided source buffer and write to channel
     *
     * @param sourceBuffer Buffer containing bytes to be encrypted and serialized
     * @return Bytes read from the source buffer and written to the output channel
     * @throws IOException Thrown on failures writing to output channel
     */
    @Override
    public int write(final ByteBuffer sourceBuffer) throws IOException {
        Objects.requireNonNull(sourceBuffer, "Source Buffer required");

        final int sourceBufferLimit = sourceBuffer.limit();

        while (sourceBuffer.hasRemaining()) {
            final int inputBufferRemaining = inputBuffer.remaining();
            final int sourceBufferRemaining = sourceBuffer.remaining();
            if (sourceBufferRemaining > inputBufferRemaining) {
                final int sourceBufferInputLimit = sourceBuffer.position() + inputBufferRemaining;
                sourceBuffer.limit(sourceBufferInputLimit);
            }

            inputBuffer.put(sourceBuffer);
            sourceBuffer.limit(sourceBufferLimit);

            if (inputBuffer.remaining() == 0) {
                flushInputBuffer();
            }
        }

        return sourceBufferLimit;
    }

    /**
     * Return Channel open status
     *
     * @return Channel open status according to output channel
     */
    @Override
    public boolean isOpen() {
        return outputChannel.isOpen();
    }

    /**
     * Close flushes remaining buffer with last chunk flag and closes Output Channel
     *
     * @throws IOException Thrown on failures to flush buffer or close channel
     */
    @Override
    public void close() throws IOException {
        if (inputBuffer.position() > 0) {
            payloadIvParameterSpec.setLastChunkFlag();
            flushInputBuffer();
        }

        outputChannel.close();
        payloadKey.destroy();
    }

    private void flushInputBuffer() throws IOException {
        inputBuffer.flip();

        try {
            final ByteBufferEncryptor byteBufferEncryptor = ByteBufferCipherOperationFactory.newByteBufferEncryptor(payloadKey, payloadIvParameterSpec);
            byteBufferEncryptor.encrypt(inputBuffer, outputBuffer);
        } catch (final GeneralSecurityException e) {
            final String message = String.format("Write chunk failed: counter %s", Arrays.toString(payloadIvParameterSpec.getIV()));
            throw new PayloadException(message, e);
        }

        flushOutputBuffer();
        inputBuffer.clear();
        payloadIvParameterSpec.incrementInitializationVector();
    }

    private void flushOutputBuffer() throws IOException {
        outputBuffer.flip();
        while (outputBuffer.hasRemaining()) {
            outputChannel.write(outputBuffer);
        }
        outputBuffer.clear();
    }
}
