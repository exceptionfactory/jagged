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

import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class StandardByteBufferCipherFactoryTest {
    private static final String ALGORITHM_FILTER = String.format("Cipher.%s", CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm());

    @Test
    void testNewByteBufferDecryptor() throws GeneralSecurityException {
        final IvParameterSpec parameterSpec = new IvParameterSpec(CipherFactoryTest.INITIALIZATION_VECTOR);
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final StandardByteBufferCipherFactory factory = new StandardByteBufferCipherFactory();
        final ByteBufferDecryptor decryptor = factory.newByteBufferDecryptor(cipherKey, parameterSpec);

        assertNotNull(decryptor);
    }

    @Test
    void testNewByteBufferEncryptor() throws GeneralSecurityException {
        final IvParameterSpec parameterSpec = new IvParameterSpec(CipherFactoryTest.INITIALIZATION_VECTOR);
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final StandardByteBufferCipherFactory factory = new StandardByteBufferCipherFactory();
        final ByteBufferEncryptor encryptor = factory.newByteBufferEncryptor(cipherKey, parameterSpec);

        assertNotNull(encryptor);
    }

    @Test
    void testNewByteBufferEncryptorWithProvider() throws GeneralSecurityException {
        final IvParameterSpec parameterSpec = new IvParameterSpec(CipherFactoryTest.INITIALIZATION_VECTOR);
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final Provider provider = getProvider();
        final StandardByteBufferCipherFactory factory = new StandardByteBufferCipherFactory(provider);
        final ByteBufferEncryptor encryptor = factory.newByteBufferEncryptor(cipherKey, parameterSpec);

        assertNotNull(encryptor);
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
