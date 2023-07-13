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
import com.exceptionfactory.jagged.PayloadException;
import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StandardPayloadKeyWriterTest {
    private static final String FILE_HEADER_KEYWORD = "File Header";

    private static final String PAYLOAD_NONCE_KEYWORD = "Payload Nonce";

    private static final int FILE_HEADER_SIZE = 70;

    private static final int FILE_HEADER_PAYLOAD_NONCE_SIZE = 86;

    @Mock
    private RecipientStanzaWriter recipientStanzaWriter;

    @Test
    void testWriteFileHeaderBufferLessThanFileHeader() {
        final StandardPayloadKeyWriter writer = new StandardPayloadKeyWriter();

        final ByteBuffer buffer = ByteBuffer.allocate(0);

        final PayloadException exception = assertThrows(PayloadException.class, () -> writer.writeFileHeader(buffer, Collections.emptyList()));
        assertTrue(exception.getMessage().contains(FILE_HEADER_KEYWORD));
    }

    @Test
    void testWriteFileHeaderBufferLessThanPayloadNonce() {
        final StandardPayloadKeyWriter writer = new StandardPayloadKeyWriter();

        final ByteBuffer buffer = ByteBuffer.allocate(FILE_HEADER_SIZE);

        final PayloadException exception = assertThrows(PayloadException.class, () -> writer.writeFileHeader(buffer, Collections.emptyList()));
        assertTrue(exception.getMessage().contains(PAYLOAD_NONCE_KEYWORD));
    }

    @Test
    void testWriteFileHeader() throws GeneralSecurityException, IOException {
        final StandardPayloadKeyWriter writer = new StandardPayloadKeyWriter();

        final ByteBuffer buffer = ByteBuffer.allocate(FILE_HEADER_PAYLOAD_NONCE_SIZE);

        final CipherKey payloadKey = writer.writeFileHeader(buffer, Collections.emptyList());
        assertNotNull(payloadKey);

        assertEquals(FILE_HEADER_PAYLOAD_NONCE_SIZE, buffer.position());
    }

    @Test
    void testWriteFileHeaderRecipientStanzaWriter() throws GeneralSecurityException, IOException {
        final StandardPayloadKeyWriter writer = new StandardPayloadKeyWriter();

        final ByteBuffer buffer = ByteBuffer.allocate(FILE_HEADER_PAYLOAD_NONCE_SIZE);

        when(recipientStanzaWriter.getRecipientStanzas(isA(FileKey.class))).thenReturn(Collections.emptyList());

        final CipherKey payloadKey = writer.writeFileHeader(buffer, Collections.singletonList(recipientStanzaWriter));
        assertNotNull(payloadKey);
    }
}
