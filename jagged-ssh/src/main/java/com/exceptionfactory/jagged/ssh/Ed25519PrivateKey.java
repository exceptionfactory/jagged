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
package com.exceptionfactory.jagged.ssh;

import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Ed25519 Private Key containing raw key bytes
 */
class Ed25519PrivateKey implements PrivateKey {
    private static final byte ZERO = 0;

    private final AtomicBoolean destroyed = new AtomicBoolean();

    private final byte[] encoded;

    /**
     * Ed25519 Private Key constructor with raw bytes containing private key seed
     *
     * @param encoded private key seed of 32 bytes
     */
    Ed25519PrivateKey(final byte[] encoded) {
        this.encoded = Objects.requireNonNull(encoded, "Encoded Key required");
    }

    /**
     * Get algorithm describes the type of key
     *
     * @return Algorithm is Ed25519
     */
    @Override
    public String getAlgorithm() {
        return Ed25519KeyIndicator.KEY_ALGORITHM.getIndicator();
    }

    /**
     * Get format describes the encoded content bytes
     *
     * @return Encoded key format is RAW
     */
    @Override
    public String getFormat() {
        return Ed25519KeyIndicator.KEY_FORMAT.getIndicator();
    }

    /**
     * Get encoded key bytes consisting of private key seed
     *
     * @return encoded private key array of 32 bytes
     */
    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    /**
     * Get string representation of key algorithm
     *
     * @return Key algorithm
     */
    @Override
    public String toString() {
        return getAlgorithm();
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
