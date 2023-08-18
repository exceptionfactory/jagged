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
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptor;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.BadPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class X25519RecipientStanzaReaderTest {
    private static final String EPHEMERAL_SHARE_ENCODED = "TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc";

    private static final String BODY_ENCODED = "EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U";

    private static final byte[] WRAP_KEY = new byte[]{
            -74, 29, -56, 34, 107, 97, -105, -40,
            75, -15, -9, 89, 34, -81, -21, 48,
            3, 87, 13, 100, -108, 92, 125, -9,
            100, 57, 97, -75, -41, -55, 84, -88
    };

    private static final byte[] EMPTY_BODY = new byte[]{};

    private static final CanonicalBase64.Decoder DECODER = CanonicalBase64.getDecoder();

    @Mock
    private RecipientKeyFactory recipientKeyFactory;

    @Mock
    private SharedSecretKeyProducer sharedSecretKeyProducer;

    @Mock
    private SharedWrapKeyProducer sharedWrapKeyProducer;

    @Mock
    private RecipientStanza recipientStanza;

    private X25519RecipientStanzaReader reader;

    @BeforeEach
    void setReader() {
        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory();
        final FileKeyDecryptor fileKeyDecryptor = fileKeyDecryptorFactory.newFileKeyDecryptor();
        reader = new X25519RecipientStanzaReader(recipientKeyFactory, sharedSecretKeyProducer, sharedWrapKeyProducer, fileKeyDecryptor);
    }

    @Test
    void testGetFileKeyRecipientStanzasNotFound() {
        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.emptyList()));
        final List<Throwable> suppressed = Arrays.asList(exception.getSuppressed());
        assertTrue(suppressed.isEmpty());
    }

    @Test
    void testGetFileKeyNoArguments() {
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.singleton(recipientStanza)));
        final List<Throwable> suppressed = Arrays.asList(exception.getSuppressed());
        assertFalse(suppressed.isEmpty());
    }

    @Test
    void testGetFileKeyEphemeralShareEmpty() {
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());

        final String ephemeralShare = String.class.getSimpleName();
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(ephemeralShare));

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.singleton(recipientStanza)));
        final List<Throwable> suppressed = Arrays.asList(exception.getSuppressed());
        assertFalse(suppressed.isEmpty());
    }

    @Test
    void testGetFileKeyExtraArgumentFound() {
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(EPHEMERAL_SHARE_ENCODED, String.class.getSimpleName()));

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.singleton(recipientStanza)));
        final List<Throwable> suppressed = Arrays.asList(exception.getSuppressed());
        assertFalse(suppressed.isEmpty());
    }

    @Test
    void testGetFileKeyBodyEmpty() {
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(EPHEMERAL_SHARE_ENCODED));
        when(recipientStanza.getBody()).thenReturn(EMPTY_BODY);

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.singleton(recipientStanza)));
        final List<Throwable> suppressed = Arrays.asList(exception.getSuppressed());
        assertFalse(suppressed.isEmpty());
    }

    @Test
    void testGetFileKeyBadTag() throws GeneralSecurityException {
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(EPHEMERAL_SHARE_ENCODED));

        final byte[] body = DECODER.decode(BODY_ENCODED.getBytes(StandardCharsets.ISO_8859_1));
        when(recipientStanza.getBody()).thenReturn(body);

        final CipherKey wrapKey = new CipherKey(body);
        when(sharedWrapKeyProducer.getWrapKey(any(), any())).thenReturn(wrapKey);

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.singleton(recipientStanza)));
        final Iterator<Throwable> suppressed = Arrays.asList(exception.getSuppressed()).iterator();
        assertTrue(suppressed.hasNext());
        final Throwable firstSuppressed = suppressed.next();
        assertInstanceOf(BadPaddingException.class, firstSuppressed);
    }

    @Test
    void testGetFileKey() throws GeneralSecurityException {
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(EPHEMERAL_SHARE_ENCODED));

        final byte[] body = DECODER.decode(BODY_ENCODED.getBytes(StandardCharsets.ISO_8859_1));
        when(recipientStanza.getBody()).thenReturn(body);

        final CipherKey wrapKey = new CipherKey(WRAP_KEY);
        when(sharedWrapKeyProducer.getWrapKey(any(), any())).thenReturn(wrapKey);

        final FileKey fileKey = reader.getFileKey(Collections.singleton(recipientStanza));
        assertNotNull(fileKey);
    }
}
