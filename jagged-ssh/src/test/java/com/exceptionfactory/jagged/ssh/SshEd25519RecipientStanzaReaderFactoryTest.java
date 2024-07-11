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

import com.exceptionfactory.jagged.RecipientStanzaReader;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SshEd25519RecipientStanzaReaderFactoryTest {
    private static final String ALGORITHM_FILTER = String.format("KeyAgreement.%s", EllipticCurveKeyType.X25519.getAlgorithm());

    @Test
    void testNewRecipientStanzaReaderOpenSshKey() throws GeneralSecurityException, IOException {
        final byte[] encoded = getOpenSshKeyEncoded();

        final RecipientStanzaReader reader = SshEd25519RecipientStanzaReaderFactory.newRecipientStanzaReader(encoded);

        assertNotNull(reader);
    }

    @Test
    void testNewRecipientStanzaReaderOpenSshKeyWithProvider() throws GeneralSecurityException, IOException {
        final byte[] encoded = getOpenSshKeyEncoded();
        final Provider provider = getProvider();

        final RecipientStanzaReader reader = SshEd25519RecipientStanzaReaderFactory.newRecipientStanzaReader(encoded, provider);

        assertNotNull(reader);
    }

    private byte[] getOpenSshKeyEncoded() throws IOException {
        final ByteBuffer privateKeyBuffer = OpenSshKeyPairReaderTest.getEd25519PrivateKeyBuffer();
        final ByteBuffer inputBuffer = OpenSshKeyPairReaderTest.getKeyPairBuffer(SshKeyType.ED25519, privateKeyBuffer);
        final byte[] encoded = new byte[inputBuffer.remaining()];
        inputBuffer.get(encoded);
        return encoded;
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
