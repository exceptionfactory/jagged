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

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.Objects;

/**
 * Standard implementation of File Key Encryptor using ChaCha20-Poly1305
 */
class StandardFileKeyEncryptor implements FileKeyEncryptor {
    private final CipherFactory cipherFactory;

    /**
     * Standard File Key Encryptor uses the system default Security Provider configuration
     */
    StandardFileKeyEncryptor() {
        cipherFactory = new CipherFactory();
    }

    /**
     * Standard File Key Encryptor with support for custom Security Provider
     *
     * @param provider Security Provider supporting ChaCha20-Poly1305
     */
    StandardFileKeyEncryptor(final Provider provider) {
        cipherFactory = new CipherFactory(provider);
    }

    /**
     * Get Encrypted File Key from File Key
     *
     * @param fileKey File Key
     * @param cipherKey Cipher Key for encrypting File Key
     * @return Encrypted File Key
     * @throws GeneralSecurityException Thrown on failure of encryption operations
     */
    @Override
    public EncryptedFileKey getEncryptedFileKey(final FileKey fileKey, final CipherKey cipherKey) throws GeneralSecurityException {
        Objects.requireNonNull(fileKey, "File Key required");
        Objects.requireNonNull(cipherKey, "Cipher Key required");

        final PayloadIvParameterSpec parameterSpec = new PayloadIvParameterSpec();
        final Cipher cipher = cipherFactory.getInitializedCipher(CipherFactory.CipherMode.ENCRYPT, cipherKey, parameterSpec);

        final byte[] fileKeyEncoded = fileKey.getEncoded();
        final byte[] encryptedFileKey = cipher.doFinal(fileKeyEncoded);
        return new EncryptedFileKey(encryptedFileKey);
    }
}
