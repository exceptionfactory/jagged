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
import java.security.PublicKey;
import java.util.Objects;

/**
 * X25519 Public Key containing Bech32 encoded key bytes
 */
class X25519PublicKey implements PublicKey {
    private final byte[] encoded;

    /**
     * X25519 Public Key constructor with Bech32 encoded characters
     *
     * @param encoded Bech32 character array of 62 bytes
     */
    X25519PublicKey(final byte[] encoded) {
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
     * Get ASCII string representation of the age encryption X25519 public key encoded using Bech32
     *
     * @return Bech32 encoded public key
     */
    @Override
    public String toString() {
        return new String(encoded, StandardCharsets.US_ASCII);
    }
}
