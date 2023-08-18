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

class StandardFileKeyDecryptorTest {
    private static final String ALGORITHM_FILTER = String.format("Cipher.%s", CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm());

    @Test
    void testGetFileKey() throws GeneralSecurityException {
        final FileKey fileKey = new FileKey();
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final FileKeyEncryptorFactory fileKeyEncryptorFactory = new FileKeyEncryptorFactory();
        final FileKeyEncryptor fileKeyEncryptor = fileKeyEncryptorFactory.newFileKeyEncryptor();
        final EncryptedFileKey encryptedFileKey = fileKeyEncryptor.getEncryptedFileKey(fileKey, cipherKey);

        final StandardFileKeyDecryptor decryptor = new StandardFileKeyDecryptor();
        final FileKey decryptedFileKey = decryptor.getFileKey(encryptedFileKey, cipherKey);

        assertEquals(fileKey, decryptedFileKey);
    }

    @Test
    void testGetFileKeyWithProvider() throws GeneralSecurityException {
        final FileKey fileKey = new FileKey();
        final CipherKey cipherKey = new CipherKey(CipherKeyTest.SYMMETRIC_KEY);

        final Provider provider = getProvider();

        final FileKeyEncryptorFactory fileKeyEncryptorFactory = new FileKeyEncryptorFactory(provider);
        final FileKeyEncryptor fileKeyEncryptor = fileKeyEncryptorFactory.newFileKeyEncryptor();
        final EncryptedFileKey encryptedFileKey = fileKeyEncryptor.getEncryptedFileKey(fileKey, cipherKey);

        final StandardFileKeyDecryptor decryptor = new StandardFileKeyDecryptor(provider);
        final FileKey decryptedFileKey = decryptor.getFileKey(encryptedFileKey, cipherKey);

        assertEquals(fileKey, decryptedFileKey);
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
