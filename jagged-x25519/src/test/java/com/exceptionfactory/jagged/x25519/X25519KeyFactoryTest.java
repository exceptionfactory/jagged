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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class X25519KeyFactoryTest {
    private static final String ALGORITHM_FILTER = String.format("KeyAgreement.%s", RecipientIndicator.KEY_ALGORITHM.getIndicator());

    private static final String PRIVATE_KEY = "AGE-SECRET-KEY-1N9JEPW6DWJ0ZQUDX63F5A03GX8QUW7PXDE39N8UYF82VZ9PC8UFS3M7XA9";

    private static final String PUBLIC_KEY = "age1lvyvwawkr0mcnnnncaghunadrqkmuf9e6507x9y920xxpp866cnql7dp2z";

    @Mock
    private Key unsupportedKey;

    private X25519KeyFactory keyFactory;

    @BeforeEach
    void setKeyFactory() throws GeneralSecurityException {
        keyFactory = new X25519KeyFactory();
    }

    @Test
    void testGeneratePublic() {
        final SecretKeySpec keySpec = getSecretKeySpec();

        assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePublic(keySpec));
    }

    @Test
    void testGeneratePrivate() {
        final SecretKeySpec keySpec = getSecretKeySpec();

        assertThrows(InvalidKeySpecException.class, () -> keyFactory.generatePrivate(keySpec));
    }

    @Test
    void testGetKeySpec() {
        final SecretKeySpec keySpec = getSecretKeySpec();

        assertThrows(InvalidKeySpecException.class, () -> keyFactory.getKeySpec(keySpec, SecretKeySpec.class));
    }

    @Test
    void testTranslateKey() throws InvalidKeyException {
        final SecretKeySpec keySpec = getSecretKeySpec();

        final Key publicKey = keyFactory.translateKey(keySpec);

        assertNotNull(publicKey);
        assertEquals(PUBLIC_KEY, publicKey.toString());
    }

    @Test
    void testTranslateKeyProviderSpecified() throws GeneralSecurityException {
        final SecretKeySpec keySpec = getSecretKeySpec();

        final Provider provider = getProvider();
        final X25519KeyFactory configuredKeyFactory = new X25519KeyFactory(provider);
        final Key publicKey = configuredKeyFactory.translateKey(keySpec);

        assertNotNull(publicKey);
        assertEquals(PUBLIC_KEY, publicKey.toString());
    }

    @Test
    void testTranslateKeyNotSupported() {
        assertThrows(InvalidKeyException.class, () -> keyFactory.translateKey(unsupportedKey));
    }

    @Test
    void testTranslateKeyInvalidPublicKey() {
        final byte[] publicKeyEncoded = PUBLIC_KEY.getBytes(StandardCharsets.US_ASCII);
        final SecretKeySpec keySpec = new SecretKeySpec(publicKeyEncoded, RecipientIndicator.KEY_ALGORITHM.getIndicator());

        assertThrows(InvalidKeyException.class, () -> keyFactory.translateKey(keySpec));
    }

    private SecretKeySpec getSecretKeySpec() {
        final byte[] privateKeyEncoded = PRIVATE_KEY.getBytes(StandardCharsets.US_ASCII);
        return new SecretKeySpec(privateKeyEncoded, RecipientIndicator.KEY_ALGORITHM.getIndicator());
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
