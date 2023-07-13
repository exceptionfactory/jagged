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

import java.security.SecureRandom;

/**
 * Payload nonce consisting of 16 bytes from a cryptographically secure pseudorandom number generator
 */
public final class PayloadNonceKey extends MacKey {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Payload nonce key constructor generates a new key using java.util.SecureRandom.nextBytes()
     */
    public PayloadNonceKey() {
        this(getSecureRandomKey());
    }

    /**
     * Payload nonce key with required byte array
     *
     * @param key Nonce consisting of 16 bytes
     */
    public PayloadNonceKey(final byte[] key) {
        super(key, CryptographicKeyType.PAYLOAD_NONCE);
    }

    private static byte[] getSecureRandomKey() {
        final byte[] key = new byte[CryptographicKeyType.PAYLOAD_NONCE.getKeyLength()];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }
}
