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
 * Cryptographic Algorithm references
 */
enum CryptographicAlgorithm {
    /** ChaCha20-Poly1305 Authenticated Encryption with Associated Data algorithm defined in RFC 7539 */
    CHACHA20_POLY1305("ChaCha20-Poly1305"),

    /** Keyed-Hash Message Authentication Code with SHA-256 defined in RFC 2104 */
    HMACSHA256("HmacSHA256");

    private final String algorithm;

    CryptographicAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Get algorithm name as defined according to Java Security Standard Names
     *
     * @return Java Security Standard Name for Cipher Algorithm
     */
    String getAlgorithm() {
        return algorithm;
    }
}
