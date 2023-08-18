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

import com.exceptionfactory.jagged.FileKey;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StandardFileKeyEncryptorTest {
    private static final String ALGORITHM_FILTER = String.format("Cipher.%s", CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm());

    @Test
    void testGetEncryptedFileKey() throws GeneralSecurityException {
        final FileKey fileKey = new FileKey();
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final StandardFileKeyEncryptor encryptor = new StandardFileKeyEncryptor();
        final EncryptedFileKey encryptedFileKey = encryptor.getEncryptedFileKey(fileKey, cipherKey);

        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory();
        final FileKeyDecryptor fileKeyDecryptor = fileKeyDecryptorFactory.newFileKeyDecryptor();
        final FileKey decryptedFileKey = fileKeyDecryptor.getFileKey(encryptedFileKey, cipherKey);

        assertEquals(fileKey, decryptedFileKey);
    }

    @Test
    void testGetEncryptedFileKeyWithProvider() throws GeneralSecurityException {
        final FileKey fileKey = new FileKey();
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final Provider provider = getProvider();
        final StandardFileKeyEncryptor encryptor = new StandardFileKeyEncryptor(provider);
        final EncryptedFileKey encryptedFileKey = encryptor.getEncryptedFileKey(fileKey, cipherKey);

        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory(provider);
        final FileKeyDecryptor fileKeyDecryptor = fileKeyDecryptorFactory.newFileKeyDecryptor();
        final FileKey decryptedFileKey = fileKeyDecryptor.getFileKey(encryptedFileKey, cipherKey);

        assertEquals(fileKey, decryptedFileKey);
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
