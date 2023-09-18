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
package com.exceptionfactory.jagged.framework.format;

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StandardPayloadKeyReaderTest {
    private static final int EMPTY_BUFFER_CAPACITY = 0;

    private static final int INITIAL_BUFFER_POSITION = 0;

    private static final int RECIPIENT_STANZA_POSITION = 22;

    private static final int RECIPIENT_STANZA_READ_POSITION = 59;

    private static final int RECIPIENT_STANZA_PAYLOAD_NONCE_READ_POSITION = 75;

    private static final int PAYLOAD_NONCE_READ_POSITION = 16;

    @Mock
    private RecipientStanzaReader recipientStanzaReader;

    @Mock
    private FileKeyReader fileKeyReader;

    private StandardPayloadKeyReader reader;

    private Iterable<RecipientStanzaReader> recipientStanzaReaders;

    @BeforeEach
    void setReader() {
        reader = new StandardPayloadKeyReader(fileKeyReader);
        recipientStanzaReaders = Collections.singletonList(recipientStanzaReader);
    }

    @Test
    void testGetPayloadKeyInvalidKey() throws IOException {
        reader = new StandardPayloadKeyReader();

        final ByteBuffer buffer = StandardFileHeaderReaderTest.getFileHeaderBuffer();

        assertThrows(InvalidKeyException.class, () -> reader.getPayloadKey(buffer, recipientStanzaReaders));
        assertEquals(INITIAL_BUFFER_POSITION, buffer.position());
    }

    @Test
    void testGetPayloadKeyUnsupportedRecipientStanzaException() throws IOException {
        reader = new StandardPayloadKeyReader();

        final ByteBuffer buffer = StandardFileHeaderReaderTest.getFileHeaderBuffer();

        final Iterable<RecipientStanzaReader> readers = Arrays.asList(recipientStanzaReader, recipientStanzaReader);
        assertThrows(UnsupportedRecipientStanzaException.class, () -> reader.getPayloadKey(buffer, readers));
        assertEquals(INITIAL_BUFFER_POSITION, buffer.position());
    }

    @Test
    void testGetPayloadKey() throws GeneralSecurityException, IOException {
        final ByteBuffer buffer = StandardFileHeaderReaderTest.getFileHeaderBuffer();

        final FileKey fileKey = new FileKey(StandardFileKeyHeaderTest.FILE_KEY.clone());
        when(fileKeyReader.readFileKey(eq(buffer), eq(recipientStanzaReader))).thenReturn(fileKey);

        final CipherKey payloadKey = reader.getPayloadKey(buffer, recipientStanzaReaders);

        assertNotNull(payloadKey);
        assertEquals(PAYLOAD_NONCE_READ_POSITION, buffer.position());
    }

    @Test
    void testGetPayloadKeySuccessThenException() throws GeneralSecurityException, IOException {
        final ByteBuffer buffer = StandardFileHeaderReaderTest.getFileHeaderBuffer();

        final FileKey fileKey = new FileKey(StandardFileKeyHeaderTest.FILE_KEY.clone());
        when(recipientStanzaReader.getFileKey(anyCollection())).thenReturn(fileKey).thenThrow(new InvalidKeyException());
        final List<RecipientStanzaReader> readers = Arrays.asList(recipientStanzaReader, recipientStanzaReader);

        final MockFileKeyReader mockFileKeyReader = new MockFileKeyReader();
        final StandardPayloadKeyReader payloadKeyReader = new StandardPayloadKeyReader(mockFileKeyReader);
        buffer.position(RECIPIENT_STANZA_POSITION);

        final CipherKey payloadKey = payloadKeyReader.getPayloadKey(buffer, readers);

        assertNotNull(payloadKey);
        assertEquals(RECIPIENT_STANZA_PAYLOAD_NONCE_READ_POSITION, buffer.position());
    }

    @Test
    void testGetPayloadKeyException() throws GeneralSecurityException, IOException {
        final ByteBuffer buffer = ByteBuffer.allocate(EMPTY_BUFFER_CAPACITY);

        final FileKey fileKey = new FileKey(StandardFileKeyHeaderTest.FILE_KEY.clone());
        when(fileKeyReader.readFileKey(eq(buffer), eq(recipientStanzaReader))).thenReturn(fileKey);

        assertThrows(InvalidParameterSpecException.class, () -> reader.getPayloadKey(buffer, recipientStanzaReaders));
    }

    private static class MockFileKeyReader implements FileKeyReader {

        @Override
        public FileKey readFileKey(final ByteBuffer buffer, final RecipientStanzaReader recipientStanzaReader) throws GeneralSecurityException {
            buffer.position(RECIPIENT_STANZA_READ_POSITION);
            return recipientStanzaReader.getFileKey(Collections.emptyList());
        }
    }
}
