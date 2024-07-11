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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class X25519KeyAgreementFactoryTest {
    private static final String ALGORITHM_FILTER = String.format("KeyAgreement.%s", EllipticCurveKeyType.X25519.getAlgorithm());

    private static PrivateKey privateKey;

    @BeforeAll
    static void setPrivateKey() throws NoSuchAlgorithmException {
        final X25519KeyPairGeneratorFactory keyPairGeneratorFactory = new X25519KeyPairGeneratorFactory();
        final KeyPairGenerator keyPairGenerator = keyPairGeneratorFactory.getKeyPairGenerator();
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
    }

    @Test
    void testGetInitializedKeyAgreement() throws GeneralSecurityException {
        final X25519KeyAgreementFactory keyAgreementFactory = new X25519KeyAgreementFactory();
        final KeyAgreement keyAgreement = keyAgreementFactory.getInitializedKeyAgreement(privateKey);

        assertNotNull(keyAgreement);
    }

    @Test
    void testGetInitializedKeyAgreementWithProvider() throws GeneralSecurityException {
        final Provider provider = getProvider();
        final X25519KeyAgreementFactory keyAgreementFactory = new X25519KeyAgreementFactory(provider);
        final KeyAgreement keyAgreement = keyAgreementFactory.getInitializedKeyAgreement(privateKey);

        assertNotNull(keyAgreement);
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
