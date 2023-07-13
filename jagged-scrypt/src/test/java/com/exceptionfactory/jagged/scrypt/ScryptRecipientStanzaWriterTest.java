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

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanza;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScryptRecipientStanzaWriterTest {
    private static final byte[] PASSPHRASE = String.class.getName().getBytes(StandardCharsets.UTF_8);

    private static final int MINIMUM_WORK_FACTOR = 2;

    private static final int ARGUMENT_LENGTH = 22;

    private static final int BODY_LENGTH = 32;

    private static FileKey fileKey;

    private ScryptRecipientStanzaWriter writer;

    @BeforeAll
    static void setFileKey() {
        fileKey = new FileKey();
    }

    @BeforeEach
    void setWriter() {
        final ScryptDerivedWrapKeyProducer derivedWrapKeyProducer = new ScryptDerivedWrapKeyProducer(PASSPHRASE);
        writer = new ScryptRecipientStanzaWriter(derivedWrapKeyProducer, MINIMUM_WORK_FACTOR);
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

        assertTrue(arguments.hasNext());
        final String secondArgument = arguments.next();
        assertEquals(Integer.toString(MINIMUM_WORK_FACTOR), secondArgument);

        assertFalse(arguments.hasNext());

        assertEquals(BODY_LENGTH, recipientStanza.getBody().length);
    }
}
