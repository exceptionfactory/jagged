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
package com.exceptionfactory.jagged.framework.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CipherFactoryTest {
    static final byte[] INITIALIZATION_VECTOR = new byte[]{
            1, 2, 3, 4, 5, 6,
            1, 2, 3, 4, 5, 6
    };

    private static final String PROVIDER_FILTER = String.format("Cipher.%s", CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm());

    @Test
    void testGetInitializedCipherEncryptMode() throws GeneralSecurityException {
        final IvParameterSpec parameterSpec = new IvParameterSpec(INITIALIZATION_VECTOR);
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final CipherFactory cipherFactory = new CipherFactory();
        final Cipher cipher = cipherFactory.getInitializedCipher(CipherFactory.CipherMode.ENCRYPT, cipherKey, parameterSpec);

        assertNotNull(cipher);
        assertEquals(CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm(), cipher.getAlgorithm());
        assertArrayEquals(INITIALIZATION_VECTOR, cipher.getIV());
    }

    @Test
    void testGetInitializedCipherDecryptMode() throws GeneralSecurityException {
        final IvParameterSpec parameterSpec = new IvParameterSpec(INITIALIZATION_VECTOR);
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final CipherFactory cipherFactory = new CipherFactory();
        final Cipher cipher = cipherFactory.getInitializedCipher(CipherFactory.CipherMode.DECRYPT, cipherKey, parameterSpec);

        assertCipherEquals(cipher);
    }

    @Test
    void testGetInitializedCipherProvider() throws GeneralSecurityException {
        final IvParameterSpec parameterSpec = new IvParameterSpec(INITIALIZATION_VECTOR);
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final Provider provider = getProvider();
        final CipherFactory cipherFactory = new CipherFactory(provider);
        final Cipher cipher = cipherFactory.getInitializedCipher(CipherFactory.CipherMode.ENCRYPT, cipherKey, parameterSpec);

        assertNotNull(cipher);
        assertEquals(CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm(), cipher.getAlgorithm());
        assertArrayEquals(INITIALIZATION_VECTOR, cipher.getIV());
    }

    private void assertCipherEquals(final Cipher cipher) {
        assertNotNull(cipher);
        assertEquals(CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm(), cipher.getAlgorithm());
        assertArrayEquals(INITIALIZATION_VECTOR, cipher.getIV());
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(PROVIDER_FILTER);
        return providers[0];
    }
}
