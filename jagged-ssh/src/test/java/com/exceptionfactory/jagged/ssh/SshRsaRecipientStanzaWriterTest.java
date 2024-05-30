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

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanza;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SshRsaRecipientStanzaWriterTest {
    private static final int FINGERPRINT_LENGTH = 6;

    private static final int EXPECTED_BODY_LENGTH = 512;

    private static FileKey fileKey;

    private static RSAPublicKey rsaPublicKey;

    private SshRsaRecipientStanzaWriter writer;

    @BeforeAll
    static void setFileKey() throws NoSuchAlgorithmException {
        fileKey = new FileKey();
        rsaPublicKey = RsaKeyPairProvider.getRsaPublicKey();
    }

    @BeforeEach
    void setWriter() {
        writer = new SshRsaRecipientStanzaWriter(rsaPublicKey);
    }

    @Test
    void testGetRecipientStanzas() throws GeneralSecurityException {
        final Iterable<RecipientStanza> recipientStanzas = writer.getRecipientStanzas(fileKey);

        assertNotNull(recipientStanzas);

        final Iterator<RecipientStanza> stanzas = recipientStanzas.iterator();
        assertTrue(stanzas.hasNext());

        final RecipientStanza recipientStanza = stanzas.next();
        final byte[] body = recipientStanza.getBody();
        assertNotNull(body);
        assertEquals(EXPECTED_BODY_LENGTH, body.length);

        assertFalse(stanzas.hasNext());
        assertEquals(SshRsaRecipientIndicator.STANZA_TYPE.getIndicator(), recipientStanza.getType());

        final Iterator<String> arguments = recipientStanza.getArguments().iterator();
        assertTrue(arguments.hasNext());

        final String fingerprint = arguments.next();
        assertFalse(arguments.hasNext());
        assertNotNull(fingerprint);
        assertEquals(FINGERPRINT_LENGTH, fingerprint.length());
    }
}
