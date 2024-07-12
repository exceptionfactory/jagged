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
package com.exceptionfactory.jagged.ssh;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SshEd25519PublicKeyReaderTest {
    private static final int BUFFER_SIZE = 128;

    private static final int REQUIRED_LENGTH = 68;

    private static final byte[] ALGORITHM = SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator().getBytes(StandardCharsets.UTF_8);

    private static final byte SPACE_SEPARATOR = 32;

    private static final int SHORT_BLOCK = 16;

    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();

    private final SshEd25519PublicKeyReader reader = new SshEd25519PublicKeyReader();

    @Test
    void testRead() throws Exception {
        final ByteBuffer inputBuffer = getPublicKeyBuffer();

        final Ed25519PublicKey publicKey = reader.read(inputBuffer);

        assertNotNull(publicKey);
    }

    @Test
    void testReadAlgorithmNotFound() {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);

        final InvalidKeyException exception = assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator()));
    }

    @Test
    void testReadSpaceNotFound() {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        inputBuffer.put(ALGORITHM);
        inputBuffer.put(ALGORITHM);
        inputBuffer.flip();

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadLengthLessThanRequired() {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        inputBuffer.put(ALGORITHM);
        inputBuffer.put(SPACE_SEPARATOR);
        inputBuffer.flip();

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    @Test
    void testReadEncodedAlgorithmNotFound() {
        final byte[] empty = new byte[REQUIRED_LENGTH];
        final byte[] encoded = ENCODER.encode(empty);

        final ByteBuffer inputBuffer = getInputBuffer(encoded);

        final InvalidKeyException exception = assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator()));
    }

    @Test
    void testReadEncodedKeyBlockLengthNotValid() {
        final ByteBuffer marshalled = ByteBuffer.allocate(REQUIRED_LENGTH);
        marshalled.putInt(ALGORITHM.length);
        marshalled.put(ALGORITHM);
        marshalled.putInt(REQUIRED_LENGTH);

        final byte[] encoded = ENCODER.encode(marshalled.array());
        final ByteBuffer inputBuffer = getInputBuffer(encoded);

        final InvalidKeyException exception = assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(Integer.toString(REQUIRED_LENGTH)));
    }

    @Test
    void testReadEncodedKeyBlockLengthNotExpected() {
        final ByteBuffer marshalled = ByteBuffer.allocate(REQUIRED_LENGTH);
        marshalled.putInt(ALGORITHM.length);
        marshalled.put(ALGORITHM);
        marshalled.putInt(SHORT_BLOCK);

        final byte[] encoded = ENCODER.encode(marshalled.array());
        final ByteBuffer inputBuffer = getInputBuffer(encoded);

        final InvalidKeyException exception = assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(Integer.toString(SHORT_BLOCK)));
    }

    static ByteBuffer getPublicKeyBuffer() {
        final SshEd25519PublicKeyMarshaller publicKeyMarshaller = new SshEd25519PublicKeyMarshaller();

        final byte[] marshalledKey = publicKeyMarshaller.getMarshalledKey(Ed25519KeyPairProvider.getPublicKey());
        final byte[] encodedKey = ENCODER.encode(marshalledKey);

        return getInputBuffer(encodedKey);
    }

    private static ByteBuffer getInputBuffer(final byte[] encodedKey) {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);

        inputBuffer.put(ALGORITHM);
        inputBuffer.put(SPACE_SEPARATOR);
        inputBuffer.put(encodedKey);

        inputBuffer.flip();
        return inputBuffer;
    }
}
