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

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Cryptographic Algorithm Key implementation of Secret Key with required algorithm and key length restrictions
 */
class CryptographicAlgorithmKey implements SecretKey {
    private static final String FORMAT = "RAW";

    private static final byte ZERO = 0;

    /** Destroyed status tracking */
    private final AtomicBoolean destroyed = new AtomicBoolean();

    /** Encoded key byte array */
    private final byte[] key;

    private final CryptographicAlgorithm cryptographicAlgorithm;

    /**
     * Cryptographic Algorithm Key constructor with required symmetric key
     *
     * @param key Symmetric Key
     * @param cryptographicKeyDescription Cryptographic Key Description
     * @param cryptographicAlgorithm Cryptographic Algorithm
     */
    CryptographicAlgorithmKey(final byte[] key, final CryptographicKeyDescription cryptographicKeyDescription, final CryptographicAlgorithm cryptographicAlgorithm) {
        this(getValidatedKey(key, cryptographicKeyDescription), cryptographicAlgorithm);
    }

    private CryptographicAlgorithmKey(final byte[] validatedKey, final CryptographicAlgorithm cryptographicAlgorithm) {
        this.key = validatedKey;
        this.cryptographicAlgorithm = Objects.requireNonNull(cryptographicAlgorithm, "Algorithm required");
    }

    /**
     * Get Cryptographic Algorithm for which the key will be used
     *
     * @return Cryptographic Algorithm
     */
    @Override
    public String getAlgorithm() {
        return cryptographicAlgorithm.getAlgorithm();
    }

    /**
     * Get Key format returns RAW indicating encoded key contains raw bytes
     *
     * @return Format name of RAW
     */
    @Override
    public String getFormat() {
        return FORMAT;
    }

    /**
     * Get encoded key bytes
     *
     * @return Encoded Key byte array
     */
    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    /**
     * Destroy Key so that it cannot be used for subsequent operations
     */
    @Override
    public void destroy() {
        Arrays.fill(key, ZERO);
        destroyed.set(true);
    }

    /**
     * Return destroyed status
     *
     * @return Key destroyed status
     */
    @Override
    public boolean isDestroyed() {
        return destroyed.get();
    }

    private static byte[] getValidatedKey(final byte[] key, final CryptographicKeyDescription cryptographicKeyDescription) {
        Objects.requireNonNull(key, "Symmetric Key required");
        Objects.requireNonNull(cryptographicKeyDescription, "Cryptographic Key Description required");
        final int cryptographicKeyLength = cryptographicKeyDescription.getKeyLength();
        if (cryptographicKeyLength == key.length) {
            return key;
        } else {
            final String message = String.format("Symmetric Key Length [%d] not equal to required length [%d]", key.length, cryptographicKeyLength);
            throw new IllegalArgumentException(message);
        }
    }
}
