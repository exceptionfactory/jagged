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
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptor;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScryptRecipientStanzaReaderTest {
    static final byte[] ENCRYPTED_BODY = new byte[]{
            -127, 72, -60, -54, 97, 74, 49, 85,
            -48, 16, -89, 76, 48, 114, -10, -30,
            -122, 30, -58, 49, 55, 76, -128, -76,
            59, 76, -58, 74, -94, 118, 105, 70
    };

    private static final byte[] PASSPHRASE = new byte[]{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

    private static final String ENCODED_SALT = "rF0/NwblUHHTpgQgRpe5CQ";

    private static final String WORK_FACTOR = "10";

    private static final String REJECTED_TYPE = String.class.getSimpleName();

    private static final String NOT_VALID_WORK_FACTOR = "00";

    private static final String WORK_FACTOR_LESS_THAN_MINIMUM = "1";

    private static final String WORK_FACTOR_GREATER_THAN_MAXIMUM = "21";

    private static final byte[] EMPTY_BODY = new byte[]{};

    @Mock
    private DerivedWrapKeyProducer derivedWrapKeyProducer;

    @Mock
    private RecipientStanza recipientStanza;

    private ScryptRecipientStanzaReader reader;

    @BeforeEach
    void setReader() {
        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory();
        reader = new ScryptRecipientStanzaReader(derivedWrapKeyProducer, fileKeyDecryptorFactory.newFileKeyDecryptor());
    }

    @Test
    void testGetFileKeyEmptyRecipientStanzas() {
        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(Collections.emptyList()));
    }

    @Test
    void testGetFileKeyRecipientStanzaTypeRejected()  {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(REJECTED_TYPE);

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
        assertTrue(exception.getMessage().contains(REJECTED_TYPE));
    }

    @Test
    void testGetFileKeyMultipleRecipientStanzasNotAllowed() {
        final List<RecipientStanza> stanzas = Arrays.asList(recipientStanza, recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeySaltArgumentNotFound() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.emptyList());

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
        final List<Throwable> suppressed = Arrays.asList(exception.getSuppressed());
        assertFalse(suppressed.isEmpty());
    }

    @Test
    void testGetFileKeySaltArgumentLengthNotValid() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        final String saltArgument = String.class.getSimpleName();
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(saltArgument));

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
        final String saltArgumentLength = Integer.toString(saltArgument.length());
        assertSuppressedExceptionMessageContains(exception, saltArgumentLength);
    }

    @Test
    void testGetFileKeyWorkFactorArgumentNotFound() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Collections.singletonList(ENCODED_SALT));

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
        final List<Throwable> suppressed = Arrays.asList(exception.getSuppressed());
        assertFalse(suppressed.isEmpty());
    }

    @Test
    void testGetFileKeyWorkFactorArgumentNotValid() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(ENCODED_SALT, NOT_VALID_WORK_FACTOR));

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
        assertSuppressedExceptionMessageContains(exception, NOT_VALID_WORK_FACTOR);
    }

    @Test
    void testGetFileKeyWorkFactorArgumentLessThanMinimum() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(ENCODED_SALT, WORK_FACTOR_LESS_THAN_MINIMUM));

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
        assertSuppressedExceptionMessageContains(exception, WORK_FACTOR_LESS_THAN_MINIMUM);
    }

    @Test
    void testGetFileKeyWorkFactorArgumentGreaterThanMaximum() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(ENCODED_SALT, WORK_FACTOR_GREATER_THAN_MAXIMUM));

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
        assertSuppressedExceptionMessageContains(exception, WORK_FACTOR_GREATER_THAN_MAXIMUM);
    }

    @Test
    void testGetFileKeyExtraArgumentFound() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(ENCODED_SALT, WORK_FACTOR, String.class.getSimpleName()));

        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
    }

    @Test
    void testGetFileKeyBodyEmpty() {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(ENCODED_SALT, WORK_FACTOR));
        when(recipientStanza.getBody()).thenReturn(EMPTY_BODY);

        final UnsupportedRecipientStanzaException exception = assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getFileKey(stanzas));
        final String bodyLength = Integer.toString(EMPTY_BODY.length);
        assertSuppressedExceptionMessageContains(exception, bodyLength);
    }

    @Test
    void testGetFileKey() throws GeneralSecurityException {
        final List<RecipientStanza> stanzas = Collections.singletonList(recipientStanza);
        when(recipientStanza.getType()).thenReturn(RecipientIndicator.STANZA_TYPE.getIndicator());
        when(recipientStanza.getArguments()).thenReturn(Arrays.asList(ENCODED_SALT, WORK_FACTOR));
        when(recipientStanza.getBody()).thenReturn(ENCRYPTED_BODY);

        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory();
        final FileKeyDecryptor fileKeyDecryptor = fileKeyDecryptorFactory.newFileKeyDecryptor();
        final ScryptRecipientStanzaReader stanzaReader = new ScryptRecipientStanzaReader(new ScryptDerivedWrapKeyProducer(PASSPHRASE), fileKeyDecryptor);
        final FileKey fileKey = stanzaReader.getFileKey(stanzas);

        assertNotNull(fileKey);
    }

    private void assertSuppressedExceptionMessageContains(final UnsupportedRecipientStanzaException exception, final String search) {
        final Iterator<Throwable> suppressed = Arrays.asList(exception.getSuppressed()).iterator();
        assertTrue(suppressed.hasNext());
        final Throwable suppressedException = suppressed.next();
        assertTrue(suppressedException.getMessage().contains(search));
    }
}
