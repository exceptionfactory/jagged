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

import javax.security.auth.DestroyFailedException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X25519KeyPairGeneratorTest {
    private static final String ALGORITHM_FILTER = String.format("KeyPairGenerator.%s", RecipientIndicator.KEY_ALGORITHM.getIndicator());

    private static final int PUBLIC_KEY_LENGTH = 62;

    private static final int PRIVATE_KEY_LENGTH = 74;

    @Test
    void testGenerateKeyPair() throws NoSuchAlgorithmException, DestroyFailedException {
        final X25519KeyPairGenerator keyPairGenerator = new X25519KeyPairGenerator();

        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        assertKeyPairExpected(keyPair);
        assertPrivateKeyDestroyed(keyPair.getPrivate());
    }

    @Test
    void testGenerateKeyPairWithProvider() throws NoSuchAlgorithmException, DestroyFailedException {
        final Provider provider = getProvider();
        final X25519KeyPairGenerator keyPairGenerator = new X25519KeyPairGenerator(provider);

        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        assertKeyPairExpected(keyPair);
        assertPrivateKeyDestroyed(keyPair.getPrivate());
    }

    private void assertKeyPairExpected(final KeyPair keyPair) {
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

    private void assertPrivateKeyDestroyed(final PrivateKey privateKey) throws DestroyFailedException {
        assertFalse(privateKey.isDestroyed());
        privateKey.destroy();
        assertTrue(privateKey.isDestroyed());
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
