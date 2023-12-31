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
 * Standard implementation of File Key Decryptor using ChaCha20-Poly1305
 */
class StandardFileKeyDecryptor implements FileKeyDecryptor {
    private final CipherFactory cipherFactory;

    /**
     * Standard File Key Decryptor uses the system default Security Provider configuration
     */
    StandardFileKeyDecryptor() {
        cipherFactory = new CipherFactory();
    }

    /**
     * Standard File Key Decryptor with support for custom Security Provider
     *
     * @param provider Security Provider supporting ChaCha20-Poly1305
     */
    StandardFileKeyDecryptor(final Provider provider) {
        cipherFactory = new CipherFactory(provider);
    }

    /**
     * Get File Key from Encrypted File Key
     *
     * @param encryptedFileKey Encrypted File Key
     * @param cipherKey Cipher Key for decrypting File Key
     * @return Decrypted File Key
     * @throws GeneralSecurityException Thrown on failure of decryption operations
     */
    @Override
    public FileKey getFileKey(final EncryptedFileKey encryptedFileKey, final CipherKey cipherKey) throws GeneralSecurityException {
        Objects.requireNonNull(encryptedFileKey, "Encrypted File Key required");
        Objects.requireNonNull(cipherKey, "Cipher Key required");

        final FileKeyIvParameterSpec parameterSpec = new FileKeyIvParameterSpec();
        final Cipher cipher = cipherFactory.getInitializedCipher(CipherFactory.CipherMode.DECRYPT, cipherKey, parameterSpec);

        final byte[] encryptedFileKeyEncoded = encryptedFileKey.getEncoded();
        final byte[] fileKeyEncoded = cipher.doFinal(encryptedFileKeyEncoded);
        return new FileKey(fileKeyEncoded);
    }
}
