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

import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StandardRecipientKeyFactoryTest {
    private static final byte[] EMPTY_ENCODED_KEY = new byte[]{};

    private static final String PUBLIC_KEY_ENCODED = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo";

    private static final String PRIVATE_KEY_ENCODED = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo";

    private static final CanonicalBase64.Decoder DECODER = CanonicalBase64.getDecoder();

    private StandardRecipientKeyFactory factory;

    @BeforeEach
    void setFactory() throws GeneralSecurityException {
        final KeyPairGeneratorFactory keyPairGeneratorFactory = new KeyPairGeneratorFactory();
        factory = new StandardRecipientKeyFactory(keyPairGeneratorFactory);
    }

    @Test
    void testGetPublicKeyInvalidKeyLength() {
        assertThrows(InvalidKeyException.class, () -> factory.getPublicKey(EMPTY_ENCODED_KEY));
    }

    @Test
    void testGetPublicKey() throws GeneralSecurityException {
        final byte[] publicKeyEncoded = DECODER.decode(PUBLIC_KEY_ENCODED.getBytes(StandardCharsets.US_ASCII));

        final PublicKey publicKey = factory.getPublicKey(publicKeyEncoded);

        assertNotNull(publicKey);
        final byte[] decoded = getDecoded(publicKey);
        assertArrayEquals(publicKeyEncoded, decoded);
    }

    @Test
    void testGetPrivateKeyInvalidKeyLength() {
        assertThrows(InvalidKeyException.class, () -> factory.getPrivateKey(EMPTY_ENCODED_KEY));
    }

    @Test
    void testGetPrivateKey() throws GeneralSecurityException {
        final byte[] privateKeyEncoded = DECODER.decode(PRIVATE_KEY_ENCODED.getBytes(StandardCharsets.US_ASCII));

        final PrivateKey privateKey = factory.getPrivateKey(privateKeyEncoded);

        assertNotNull(privateKey);
        final byte[] decoded = getDecoded(privateKey);
        assertArrayEquals(privateKeyEncoded, decoded);
    }

    private byte[] getDecoded(final Key key) {
        final byte[] encoded = key.getEncoded();
        final int encodedLength = encoded.length;
        final int startPosition = encodedLength - RecipientKeyType.X25519.getKeyLength();
        return Arrays.copyOfRange(encoded, startPosition, encodedLength);
    }
}
