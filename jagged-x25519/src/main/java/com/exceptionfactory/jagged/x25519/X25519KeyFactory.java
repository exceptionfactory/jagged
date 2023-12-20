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

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;

/**
 * X25519 Key Factory capable of translating Key Specifications encoded according to age-encryption.org to Public Keys
 */
public final class X25519KeyFactory extends KeyFactory {
    /**
     * X25519 Key Factory constructor with default Security Provider
     *
     * @throws GeneralSecurityException Thrown on failures to construct required collaborators
     */
    public X25519KeyFactory() throws GeneralSecurityException {
        this(new KeyAgreementFactory(), new KeyPairGeneratorFactory());
    }

    /**
     * X25519 Key Factory constructor with specified Security Provider
     *
     * @param provider Security Provider for X25519 algorithm implementation resolution
     * @throws GeneralSecurityException Thrown on failures to construct required collaborators
     */
    public X25519KeyFactory(final Provider provider) throws GeneralSecurityException {
        this(new KeyAgreementFactory(provider), new KeyPairGeneratorFactory(provider));
    }

    private X25519KeyFactory(final KeyAgreementFactory keyAgreementFactory, final KeyPairGeneratorFactory keyPairGeneratorFactory) throws GeneralSecurityException {
        super(new X25519KeyFactorySpi(keyAgreementFactory, new StandardRecipientKeyFactory(keyPairGeneratorFactory)), null, RecipientIndicator.KEY_ALGORITHM.getIndicator());
    }
}
