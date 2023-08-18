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

import com.exceptionfactory.jagged.RecipientStanzaWriter;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X25519RecipientStanzaWriterFactoryTest {
    private static final String ALGORITHM_FILTER = String.format("KeyAgreement.%s", RecipientIndicator.KEY_ALGORITHM.getIndicator());

    private static final String INVALID_HRP = "abcdef";

    private static final String INVALID_ENCODED = String.format("%s1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", INVALID_HRP);

    private static final String VALID = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj";

    @Test
    void testNewRecipientStanzaReaderInvalidHumanReadablePart() {
        final GeneralSecurityException exception = assertThrows(GeneralSecurityException.class, () ->
                X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(INVALID_ENCODED)
        );

        final String message = exception.getMessage();
        assertTrue(message.contains(INVALID_HRP));
        assertFalse(message.contains(INVALID_ENCODED));
    }

    @Test
    void testNewRecipientStanzaWriter() throws GeneralSecurityException {
        final RecipientStanzaWriter recipientStanzaWriter = X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(VALID);

        assertNotNull(recipientStanzaWriter);
    }

    @Test
    void testNewRecipientStanzaWriterWithProvider() throws GeneralSecurityException {
        final Provider provider = getProvider();
        final RecipientStanzaWriter recipientStanzaWriter = X25519RecipientStanzaWriterFactory.newRecipientStanzaWriter(VALID, provider);

        assertNotNull(recipientStanzaWriter);
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
