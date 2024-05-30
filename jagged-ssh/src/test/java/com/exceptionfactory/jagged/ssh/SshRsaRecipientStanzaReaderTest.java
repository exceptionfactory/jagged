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
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SshRsaRecipientStanzaReaderTest {
    private static final String REJECTED = String.class.getSimpleName();

    private static FileKey fileKey;

    private static RSAPublicKey rsaPublicKey;

    private static RSAPrivateCrtKey rsaPrivateKey;

    @Mock
    private RecipientStanza recipientStanza;

    private SshRsaRecipientStanzaWriter writer;

    private SshRsaRecipientStanzaReader reader;

    @BeforeAll
    static void setFileKey() throws NoSuchAlgorithmException {
        fileKey = new FileKey();
        rsaPublicKey = RsaKeyPairProvider.getRsaPublicKey();
        rsaPrivateKey = RsaKeyPairProvider.getRsaPrivateCrtKey();
    }

    @BeforeEach
    void setWriter() throws GeneralSecurityException {
        writer = new SshRsaRecipientStanzaWriter(rsaPublicKey);
        reader = new SshRsaRecipientStanzaReader(rsaPrivateKey);
    }

    @Test
    void testGetFileKeyEmptyRecipientStanzas() {
        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.emptyList()));
    }

    @Test
    void testGetFileKeyRecipientStanzaTypeRejected()  {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(REJECTED);

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyRecipientStanzaKeyFingerprintNotFound()  {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshRsaRecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.emptyList());

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyRecipientStanzaKeyFingerprintNotMatched()  {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshRsaRecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(REJECTED));

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyExtraArgumentFound() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(SshRsaRecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(REJECTED, REJECTED));

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKey() throws GeneralSecurityException {
        final Iterable<RecipientStanza> recipientStanzas = writer.getRecipientStanzas(fileKey);

        assertNotNull(recipientStanzas);

        final FileKey fileKeyRead = reader.getFileKey(recipientStanzas);

        assertNotNull(fileKeyRead);
        assertArrayEquals(fileKey.getEncoded(), fileKeyRead.getEncoded());
    }
}
