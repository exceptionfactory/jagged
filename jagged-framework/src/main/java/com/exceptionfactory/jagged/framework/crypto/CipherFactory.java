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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Factory abstraction for initialized instances of javax.crypto.Cipher with ChaCha20-Poly1305
 */
final class CipherFactory {
    private CipherFactory() {

    }

    /**
     * Get Initialized Cipher using provided arguments
     *
     * @param cipherMode Cipher Mode indicating encryption or decryption
     * @param cipherKey Cipher Symmetric Key
     * @param parameterSpec Initialization Vector parameter specification
     * @return Initialized Cipher
     * @throws GeneralSecurityException Thrown on Cipher initialization failures
     */
    static Cipher getInitializedCipher(final CipherMode cipherMode, final CipherKey cipherKey, final IvParameterSpec parameterSpec) throws GeneralSecurityException {
        Objects.requireNonNull(cipherMode, "Cipher Mode required");
        Objects.requireNonNull(cipherKey, "Cipher Symmetric Key required");
        Objects.requireNonNull(parameterSpec, "Parameter Specification required");

        final Cipher cipher = Cipher.getInstance(CryptographicAlgorithm.CHACHA20_POLY1305.getAlgorithm());
        cipher.init(cipherMode.mode, cipherKey, parameterSpec);
        return cipher;
    }

    enum CipherMode {
        DECRYPT(Cipher.DECRYPT_MODE),

        ENCRYPT(Cipher.ENCRYPT_MODE);

        private final int mode;

        CipherMode(final int mode) {
            this.mode = mode;
        }
    }
}
