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

import com.exceptionfactory.jagged.RecipientStanzaReader;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X25519RecipientStanzaReaderFactoryTest {
    private static final String INVALID_HRP = "abcdef";

    private static final String INVALID_ENCODED = String.format("%s1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", INVALID_HRP);

    private static final String VALID = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX";

    @Test
    void testNewRecipientStanzaReaderInvalidHumanReadablePart() {
        final GeneralSecurityException exception = assertThrows(GeneralSecurityException.class, () ->
                X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(INVALID_ENCODED)
        );

        final String message = exception.getMessage();
        assertTrue(message.contains(INVALID_HRP));
        assertFalse(message.contains(INVALID_ENCODED));
    }

    @Test
    void testNewRecipientStanzaReader() throws GeneralSecurityException {
        final RecipientStanzaReader recipientStanzaReader = X25519RecipientStanzaReaderFactory.newRecipientStanzaReader(VALID);

        assertNotNull(recipientStanzaReader);
    }
}
