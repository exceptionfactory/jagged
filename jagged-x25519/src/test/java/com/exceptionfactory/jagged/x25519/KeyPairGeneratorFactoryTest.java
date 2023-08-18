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

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class KeyPairGeneratorFactoryTest {
    private static final String ALGORITHM_FILTER = String.format("KeyPairGenerator.%s", RecipientIndicator.KEY_ALGORITHM.getIndicator());

    @Test
    void testGetKeyPairGenerator() throws NoSuchAlgorithmException {
        final KeyPairGeneratorFactory keyPairGeneratorFactory = new KeyPairGeneratorFactory();
        final KeyPairGenerator keyPairGenerator = keyPairGeneratorFactory.getKeyPairGenerator();

        assertNotNull(keyPairGenerator);
    }

    @Test
    void testGetKeyPairGeneratorWithProvider() throws NoSuchAlgorithmException {
        final Provider provider = getProvider();
        final KeyPairGeneratorFactory keyPairGeneratorFactory = new KeyPairGeneratorFactory(provider);
        final KeyPairGenerator keyPairGenerator = keyPairGeneratorFactory.getKeyPairGenerator();

        assertNotNull(keyPairGenerator);
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
