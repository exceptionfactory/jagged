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

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Objects;

/**
 * Factory abstraction for initialized instances of javax.crypto.KeyAgreement with X25519
 */
final class X25519KeyAgreementFactory {
    private final Provider provider;

    /**
     * Key Agreement Factory default constructor uses the system default Security Provider configuration
     */
    X25519KeyAgreementFactory() {
        provider = null;
    }

    /**
     * Key Agreement Factory constructor with support for custom Security Provider
     *
     * @param provider Security Provider supporting X25519
     */
    X25519KeyAgreementFactory(final Provider provider) {
        this.provider = Objects.requireNonNull(provider, "Provider required");
    }

    /**
     * Get Key Agreement initialized using the provided Private Key
     *
     * @param privateKey Private Key
     * @return X25519 Key Agreement
     * @throws GeneralSecurityException Thrown on initialization failures
     */
    KeyAgreement getInitializedKeyAgreement(final PrivateKey privateKey) throws GeneralSecurityException {
        final KeyAgreement keyAgreement = getKeyAgreement();
        keyAgreement.init(privateKey);
        return keyAgreement;
    }

    private KeyAgreement getKeyAgreement() throws NoSuchAlgorithmException {
        final KeyAgreement keyAgreement;

        if (provider == null) {
            keyAgreement = KeyAgreement.getInstance(EllipticCurveKeyType.X25519.getAlgorithm());
        } else {
            keyAgreement = KeyAgreement.getInstance(EllipticCurveKeyType.X25519.getAlgorithm(), provider);
        }

        return keyAgreement;
    }
}
