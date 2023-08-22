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
package com.exceptionfactory.jagged.x25519;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * X25519 Private Key containing Bech32 encoded key bytes
 */
class X25519PrivateKey implements PrivateKey {
    private static final byte ZERO = 0;

    private final AtomicBoolean destroyed = new AtomicBoolean();

    private final byte[] encoded;

    /**
     * X25519 Private Key constructor with Bech32 encoded characters
     *
     * @param encoded Bech32 character array of 74 bytes
     */
    X25519PrivateKey(final byte[] encoded) {
        this.encoded = Objects.requireNonNull(encoded, "Encoded Key required");
    }

    /**
     * Get algorithm describes the cipher operation for which the private key will be used
     *
     * @return X25519 algorithm
     */
    @Override
    public String getAlgorithm() {
        return RecipientIndicator.KEY_ALGORITHM.getIndicator();
    }

    /**
     * Get format describes the encoded content bytes
     *
     * @return Encoded key format age-encryption.org/v1/X25519
     */
    @Override
    public String getFormat() {
        return RecipientIndicator.KEY_INFORMATION.getIndicator();
    }

    /**
     * Get Bech32 encoded key bytes consisting of Human-Readable Part and encoded bytes
     *
     * @return Bech32 encoded private key bytes
     */
    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    /**
     * Get ASCII string representation of the age encryption X25519 private key encoded using Bech32
     *
     * @return Bech32 encoded private key
     */
    @Override
    public String toString() {
        return new String(encoded, StandardCharsets.US_ASCII);
    }

    /**
     * Destroy Key so that it cannot be used for subsequent operations
     */
    @Override
    public void destroy() {
        Arrays.fill(encoded, ZERO);
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
}
