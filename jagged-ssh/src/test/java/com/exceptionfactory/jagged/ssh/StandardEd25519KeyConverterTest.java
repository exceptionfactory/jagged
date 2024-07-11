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

import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandardEd25519KeyConverterTest {
    private static final String PUBLIC_KEY_CONVERTED = "r6lYp5xuYAh/v5QnHbcaCqPHRl//xBGwdOC84UOYcR0";

    private static final String PRIVATE_KEY_CONVERTED = "OFnlRqUFQJ9xJt1LyDqzl+hACateNzj38P6OxYY/piE";

    private static final String EXPECTED_FORMAT = "RAW";

    private static final CanonicalBase64.Encoder ENCODER = CanonicalBase64.getEncoder();

    private static byte[] publicKeyEncoded;

    private static byte[] privateKeyEncoded;

    private StandardEd25519KeyConverter converter;

    @BeforeAll
    static void setKeyPair() {
        publicKeyEncoded = Ed25519KeyPairProvider.getPublicKey().getEncoded();
        privateKeyEncoded = Ed25519KeyPairProvider.getPrivateKey().getEncoded();
    }

    @BeforeEach
    void setConverter() throws GeneralSecurityException {
        final X25519KeyPairGeneratorFactory keyPairGeneratorFactory = new X25519KeyPairGeneratorFactory();
        converter = new StandardEd25519KeyConverter(keyPairGeneratorFactory);
    }

    @Test
    void testGetPublicKey() throws GeneralSecurityException {
        final SharedSecretKey sharedSecretKey = new SharedSecretKey(publicKeyEncoded);
        final PublicKey publicKey = converter.getPublicKey(sharedSecretKey);

        assertNotNull(publicKey);
        final byte[] decoded = getDecoded(publicKey);
        assertArrayEquals(publicKeyEncoded, decoded);
    }

    @Test
    void testGetPublicKeyConverted() throws GeneralSecurityException {
        final Ed25519PublicKey ed25519PublicKey = new Ed25519PublicKey(publicKeyEncoded);
        final PublicKey publicKey = converter.getPublicKey(ed25519PublicKey);

        assertNotNull(publicKey);
        final byte[] decoded = getDecoded(publicKey);
        final String encoded = ENCODER.encodeToString(decoded);

        assertEquals(PUBLIC_KEY_CONVERTED, encoded);
        assertEquals(EllipticCurveKeyType.ED25519.getAlgorithm(), ed25519PublicKey.getAlgorithm());
        assertEquals(EllipticCurveKeyType.ED25519.getAlgorithm(), ed25519PublicKey.toString());
        assertEquals(EXPECTED_FORMAT, ed25519PublicKey.getFormat());
    }

    @Test
    void testGetPrivateKeyDerived() throws GeneralSecurityException {
        final SshEd25519DerivedKey derivedKey = new SshEd25519DerivedKey(privateKeyEncoded);
        final PrivateKey privateKey = converter.getPrivateKey(derivedKey);

        assertNotNull(privateKey);
        final byte[] decoded = getDecoded(privateKey);
        assertArrayEquals(privateKeyEncoded, decoded);
    }

    @Test
    void testGetPrivateKeyConverted() throws GeneralSecurityException {
        final Ed25519PrivateKey ed25519PrivateKey = new Ed25519PrivateKey(privateKeyEncoded);
        final PrivateKey privateKey = converter.getPrivateKey(ed25519PrivateKey);

        assertNotNull(privateKey);
        final byte[] decoded = getDecoded(privateKey);
        final String encoded = ENCODER.encodeToString(decoded);

        assertEquals(PRIVATE_KEY_CONVERTED, encoded);
        assertEquals(EllipticCurveKeyType.ED25519.getAlgorithm(), ed25519PrivateKey.getAlgorithm());
        assertEquals(EllipticCurveKeyType.ED25519.getAlgorithm(), ed25519PrivateKey.toString());
        assertEquals(EXPECTED_FORMAT, ed25519PrivateKey.getFormat());

        ed25519PrivateKey.destroy();
        assertTrue(ed25519PrivateKey.isDestroyed());
    }

    private byte[] getDecoded(final Key key) {
        final byte[] encoded = key.getEncoded();
        final int encodedLength = encoded.length;
        final int startPosition = encodedLength - EllipticCurveKeyType.X25519.getKeyLength();
        return Arrays.copyOfRange(encoded, startPosition, encodedLength);
    }
}
