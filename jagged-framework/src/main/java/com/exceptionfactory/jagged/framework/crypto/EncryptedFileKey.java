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
 * File Key extension of Cryptographic Algorithm Key encrypted with ChaCha20-Poly1305
 */
public final class EncryptedFileKey extends CryptographicAlgorithmKey {
    /**
     * Encrypted File Key constructor with required key byte array
     *
     * @param key Encrypted Key consisting of 32 bytes
     */
    public EncryptedFileKey(final byte[] key) {
        super(key, CryptographicKeyType.ENCRYPTED_FILE_KEY, CryptographicAlgorithm.CHACHA20_POLY1305);
    }
}
