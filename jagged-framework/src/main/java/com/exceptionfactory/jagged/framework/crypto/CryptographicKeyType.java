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

/**
 * Cryptographic Key Type references for construction and validation
 */
enum CryptographicKeyType {
    /** Extracted intermediate key for subsequent expansion */
    EXTRACTED_KEY(32),

    /** Encrypted File Key */
    ENCRYPTED_FILE_KEY(32),

    /** Header Key */
    HEADER_KEY(32),

    /** Cipher Key */
    CIPHER_KEY(32),

    /** Payload Nonce */
    PAYLOAD_NONCE(16),

    /** Shared Salt Key */
    SHARED_SALT(64),

    /** Shared Secret Key */
    SHARED_SECRET(32);

    private final int keyLength;

    CryptographicKeyType(final int keyLength) {
        this.keyLength = keyLength;
    }

    /**
     * Get key length in bytes
     *
     * @return Key length in bytes
     */
    int getKeyLength() {
        return keyLength;
    }
}
