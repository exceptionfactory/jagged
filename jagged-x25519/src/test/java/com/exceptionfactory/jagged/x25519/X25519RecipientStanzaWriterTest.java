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

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanza;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X25519RecipientStanzaWriterTest {
    static final byte[] PUBLIC_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final int ARGUMENT_LENGTH = 43;

    private static final int BODY_LENGTH = 32;

    private static FileKey fileKey;

    private X25519RecipientStanzaWriter writer;

    @BeforeAll
    static void setFileKey() {
        fileKey = new FileKey();
    }

    @BeforeEach
    void setWriter() throws GeneralSecurityException {
        final RecipientKeyFactory recipientKeyFactory = new StandardRecipientKeyFactory();
        final PublicKey recipientPublicKey = recipientKeyFactory.getPublicKey(PUBLIC_KEY);
        final SharedWrapKeyProducer sharedWrapKeyProducer = new X25519SharedWrapKeyProducer(recipientPublicKey);

        writer = new X25519RecipientStanzaWriter(recipientPublicKey, recipientKeyFactory, sharedWrapKeyProducer);
    }

    @Test
    void testGetRecipientStanzas() throws GeneralSecurityException {
        final Iterable<RecipientStanza> recipientStanzas = writer.getRecipientStanzas(fileKey);

        assertNotNull(recipientStanzas);
        final Iterator<RecipientStanza> stanzas = recipientStanzas.iterator();
        assertTrue(stanzas.hasNext());

        final RecipientStanza recipientStanza = stanzas.next();
        assertFalse(stanzas.hasNext());

        assertEquals(RecipientIndicator.STANZA_TYPE.getIndicator(), recipientStanza.getType());
        final Iterator<String> arguments = recipientStanza.getArguments().iterator();

        assertTrue(arguments.hasNext());
        final String firstArgument = arguments.next();
        assertEquals(ARGUMENT_LENGTH, firstArgument.length());

        assertFalse(arguments.hasNext());

        assertEquals(BODY_LENGTH, recipientStanza.getBody().length);
    }
}
