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

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Objects;

/**
 * Factory abstraction for instances of javax.security.KeyPairGenerator with X25519
 */
final class X25519KeyPairGeneratorFactory {
    private final Provider provider;

    /**
     * Key Pair Generator Factory default constructor uses the system default Security Provider configuration
     */
    X25519KeyPairGeneratorFactory() {
        provider = null;
    }

    /**
     * Key Pair Generator Factory constructor with support for custom Security Provider
     *
     * @param provider Security Provider supporting X25519
     */
    X25519KeyPairGeneratorFactory(final Provider provider) {
        this.provider = Objects.requireNonNull(provider, "Provider required");
    }

    KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator;

        if (provider == null) {
            keyPairGenerator = KeyPairGenerator.getInstance(EllipticCurveKeyType.X25519.getAlgorithm());
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance(EllipticCurveKeyType.X25519.getAlgorithm(), provider);
        }

        return keyPairGenerator;
    }
}
