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

import com.exceptionfactory.jagged.RecipientStanzaWriter;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SshEd25519RecipientStanzaWriterFactoryTest {
    private static final String ALGORITHM_FILTER = String.format("KeyAgreement.%s", EllipticCurveKeyType.X25519.getAlgorithm());

    @Test
    void testNewRecipientStanzaReaderOpenSshKey() throws GeneralSecurityException {
        final byte[] encoded = getSshKeyEncoded();

        final RecipientStanzaWriter writer = SshEd25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(encoded);

        assertNotNull(writer);
    }

    @Test
    void testNewRecipientStanzaReaderOpenSshKeyWithProvider() throws GeneralSecurityException {
        final byte[] encoded = getSshKeyEncoded();
        final Provider provider = getProvider();

        final RecipientStanzaWriter writer = SshEd25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(encoded, provider);

        assertNotNull(writer);
    }

    private byte[] getSshKeyEncoded() {
        final ByteBuffer publicKeyBuffer = SshEd25519PublicKeyReaderTest.getPublicKeyBuffer();
        final byte[] encoded = new byte[publicKeyBuffer.remaining()];
        publicKeyBuffer.get(encoded);
        return encoded;
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
