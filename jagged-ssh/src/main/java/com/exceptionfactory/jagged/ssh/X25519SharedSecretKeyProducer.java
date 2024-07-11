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

import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Shared Secret Key Producer using X25519 Key Agreement described in RFC 7748
 */
final class X25519SharedSecretKeyProducer implements SharedSecretKeyProducer {
    private static final boolean LAST_PHASE = true;

    private final PrivateKey privateKey;

    private final X25519KeyAgreementFactory keyAgreementFactory;

    /**
     * X25519 Shared Secret Key Producer with Private Key for initialization
     *
     * @param privateKey X25519 Private Key
     * @param keyAgreementFactory Key Agreement Factory
     */
    X25519SharedSecretKeyProducer(final PrivateKey privateKey, final X25519KeyAgreementFactory keyAgreementFactory) {
        this.privateKey = Objects.requireNonNull(privateKey, "Private Key required");
        this.keyAgreementFactory = Objects.requireNonNull(keyAgreementFactory, "Key Agreement Factory required");
    }

    /**
     * Get Shared Secret Key from X25519 Public Key
     *
     * @param publicKey X25519 Public Key
     * @return Shared Secret Key
     * @throws GeneralSecurityException Thrown on failures to generate shared secret key
     */
    @Override
    public SharedSecretKey getSharedSecretKey(final PublicKey publicKey) throws GeneralSecurityException {
        Objects.requireNonNull(publicKey, "Public Key required");
        final KeyAgreement keyAgreement = keyAgreementFactory.getInitializedKeyAgreement(privateKey);
        keyAgreement.doPhase(publicKey, LAST_PHASE);
        final byte[] secretKey = keyAgreement.generateSecret();
        return new SharedSecretKey(secretKey);
    }
}
