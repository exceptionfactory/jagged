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
package com.exceptionfactory.jagged.x25519;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X25519KeyPairGeneratorTest {
    private static final int PUBLIC_KEY_LENGTH = 62;

    private static final int PRIVATE_KEY_LENGTH = 74;

    @Test
    void testGenerateKeyPair() throws NoSuchAlgorithmException {
        final X25519KeyPairGenerator keyPairGenerator = new X25519KeyPairGenerator();

        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        assertNotNull(keyPair);

        final PublicKey publicKey = keyPair.getPublic();
        assertEquals(RecipientIndicator.KEY_ALGORITHM.getIndicator(), publicKey.getAlgorithm());
        assertEquals(RecipientIndicator.KEY_INFORMATION.getIndicator(), publicKey.getFormat());
        assertEquals(PUBLIC_KEY_LENGTH, publicKey.getEncoded().length);
        final String publicKeyEncoded = publicKey.toString();
        assertTrue(publicKeyEncoded.startsWith(RecipientIndicator.PUBLIC_KEY_HUMAN_READABLE_PART.getIndicator()));

        final PrivateKey privateKey = keyPair.getPrivate();
        assertEquals(RecipientIndicator.KEY_ALGORITHM.getIndicator(), privateKey.getAlgorithm());
        assertEquals(RecipientIndicator.KEY_INFORMATION.getIndicator(), privateKey.getFormat());
        assertEquals(PRIVATE_KEY_LENGTH, privateKey.getEncoded().length);
        final String privateKeyEncoded = privateKey.toString();
        assertTrue(privateKeyEncoded.startsWith(IdentityIndicator.PRIVATE_KEY_HUMAN_READABLE_PART.getIndicator()));
    }
}
