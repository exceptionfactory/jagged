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
package com.exceptionfactory.jagged.scrypt;

import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ScryptRecipientStanzaReaderFactoryTest {
    private static final String ALGORITHM_FILTER = "Cipher.ChaCha20-Poly1305";

    private static final byte[] PASSPHRASE = String.class.getName().getBytes(StandardCharsets.UTF_8);

    @Test
    void testNewRecipientStanzaReader() throws GeneralSecurityException {
        final RecipientStanzaReader recipientStanzaReader = ScryptRecipientStanzaReaderFactory.newRecipientStanzaReader(PASSPHRASE);

        assertNotNull(recipientStanzaReader);
    }

    @Test
    void testNewRecipientStanzaReaderNullPassphrase() {
        assertThrows(UnsupportedRecipientStanzaException.class, () -> ScryptRecipientStanzaReaderFactory.newRecipientStanzaReader(null));
    }

    @Test
    void testNewRecipientStanzaReaderWithProvider() throws GeneralSecurityException {
        final RecipientStanzaReader recipientStanzaReader = ScryptRecipientStanzaReaderFactory.newRecipientStanzaReader(PASSPHRASE, getProvider());

        assertNotNull(recipientStanzaReader);
    }

    private Provider getProvider() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers[0];
    }
}
