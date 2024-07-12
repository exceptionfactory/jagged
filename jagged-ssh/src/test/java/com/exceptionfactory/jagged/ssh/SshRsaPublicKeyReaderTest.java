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
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SshRsaPublicKeyReaderTest {
    private static final int BUFFER_SIZE = 1024;

    private static final byte[] ALGORITHM = SshRsaRecipientIndicator.STANZA_TYPE.getIndicator().getBytes(StandardCharsets.UTF_8);

    private static final byte SPACE_SEPARATOR = 32;

    private static final byte[] COMMENT = String.class.getSimpleName().getBytes(StandardCharsets.UTF_8);

    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();

    private final SshRsaPublicKeyReader reader = new SshRsaPublicKeyReader();

    @Test
    void testRead() throws Exception {
        final ByteBuffer inputBuffer = getPublicKeyBuffer();

        final RSAPublicKey publicKey = reader.read(inputBuffer);

        assertNotNull(publicKey);
    }

    @Test
    void testReadAlgorithmNotFound() {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);

        final InvalidKeyException exception = assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
        assertTrue(exception.getMessage().contains(SshRsaRecipientIndicator.STANZA_TYPE.getIndicator()));
    }

    @Test
    void testReadSpaceNotFound() {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        inputBuffer.put(ALGORITHM);
        inputBuffer.put(ALGORITHM);
        inputBuffer.flip();

        assertThrows(InvalidKeyException.class, () -> reader.read(inputBuffer));
    }

    static ByteBuffer getPublicKeyBuffer() throws NoSuchAlgorithmException {
        final SshRsaPublicKeyMarshaller publicKeyMarshaller = new SshRsaPublicKeyMarshaller();

        final byte[] marshalledKey = publicKeyMarshaller.getMarshalledKey(RsaKeyPairProvider.getRsaPublicKey());
        final byte[] encodedKey = ENCODER.encode(marshalledKey);

        return getInputBuffer(encodedKey);
    }

    private static ByteBuffer getInputBuffer(final byte[] encodedKey) {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);

        inputBuffer.put(ALGORITHM);
        inputBuffer.put(SPACE_SEPARATOR);
        inputBuffer.put(encodedKey);
        inputBuffer.put(SPACE_SEPARATOR);
        inputBuffer.put(COMMENT);

        inputBuffer.flip();
        return inputBuffer;
    }
}
