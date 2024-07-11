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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SshEd25519OpenSshKeyPairReaderTest {
    private static final int BUFFER_SIZE = 128;

    private final SshEd25519OpenSshKeyPairReader reader = new SshEd25519OpenSshKeyPairReader();

    @Test
    void testRead() throws GeneralSecurityException {
        final ByteBuffer inputBuffer = getPrivateKeyBuffer();
        final KeyPair keyPair = reader.read(inputBuffer);

        assertNotNull(keyPair);

        final PrivateKey privateKey = keyPair.getPrivate();
        assertNotNull(privateKey);
        assertArrayEquals(Ed25519KeyPairProvider.getPrivateKey().getEncoded(), privateKey.getEncoded());

        final PublicKey publicKey = keyPair.getPublic();
        assertNotNull(publicKey);
        assertArrayEquals(Ed25519KeyPairProvider.getPublicKey().getEncoded(), publicKey.getEncoded());

        assertEquals(Ed25519KeyIndicator.KEY_ALGORITHM.getIndicator(), privateKey.getAlgorithm());
        assertEquals(Ed25519KeyIndicator.KEY_ALGORITHM.getIndicator(), publicKey.getAlgorithm());
    }

    static ByteBuffer getPrivateKeyBuffer() {
        final byte[] publicKeyBlock = Ed25519KeyPairProvider.getPublicKey().getEncoded();
        final byte[] privateKeyBlock = Ed25519KeyPairProvider.getPrivateKey().getEncoded();

        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);

        inputBuffer.putInt(publicKeyBlock.length);
        inputBuffer.put(publicKeyBlock);

        final int privatePublicKeyBlockLength = privateKeyBlock.length + publicKeyBlock.length;
        inputBuffer.putInt(privatePublicKeyBlockLength);
        inputBuffer.put(privateKeyBlock);
        inputBuffer.put(publicKeyBlock);

        inputBuffer.flip();
        return inputBuffer;
    }
}
