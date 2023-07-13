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
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import com.exceptionfactory.jagged.framework.crypto.HeaderKeyProducer;
import com.exceptionfactory.jagged.framework.crypto.HeaderKeyProducerFactory;
import com.exceptionfactory.jagged.framework.crypto.MacKey;
import com.exceptionfactory.jagged.framework.crypto.MessageAuthenticationCodeProducer;
import com.exceptionfactory.jagged.framework.crypto.MessageAuthenticationCodeProducerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StandardFileKeyHeaderTest {
    static final byte[] FILE_KEY = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    static final byte[] INVALID_MAC = new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final String RECIPIENT_TYPE = "type";

    private static final String ARGUMENT = "argument";

    private static final byte[] BODY = new byte[]{1, 1};

    private static final CanonicalBase64.Encoder ENCODER = CanonicalBase64.getEncoder();

    @Mock
    private RecipientStanzaReader recipientStanzaReader;

    private StandardFileKeyReader reader;

    @BeforeEach
    void setReader() {
        reader = new StandardFileKeyReader();
    }

    @Test
    void testReadFileKey() throws GeneralSecurityException, IOException {
        final FileKey fileKey = new FileKey(FILE_KEY);
        when(recipientStanzaReader.getFileKey(any())).thenReturn(fileKey);

        final ByteBuffer buffer = getHeaderBuffer();

        final FileKey readFileKey = reader.readFileKey(buffer, recipientStanzaReader);
        assertEquals(fileKey, readFileKey);
    }

    @Test
    void testReadFileKeyNotFound() throws GeneralSecurityException, IOException {
        when(recipientStanzaReader.getFileKey(any())).thenReturn(null);

        final ByteBuffer buffer = getHeaderBuffer();

        assertThrows(InvalidKeyException.class, () -> reader.readFileKey(buffer, recipientStanzaReader));
    }

    @Test
    void testReadFileKeyHeaderNotVerified() throws GeneralSecurityException, IOException {
        final FileKey fileKey = new FileKey(FILE_KEY);
        when(recipientStanzaReader.getFileKey(any())).thenReturn(fileKey);

        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        writeRecipientTypeArgument(outputStream);
        writeRecipientBody(outputStream);
        writeInvalidMessageAuthenticationCode(outputStream);
        final byte[] bytes = outputStream.toByteArray();
        final ByteBuffer buffer = ByteBuffer.wrap(bytes);

        assertThrows(SignatureException.class, () -> reader.readFileKey(buffer, recipientStanzaReader));
    }

    private ByteBuffer getHeaderBuffer() throws IOException, GeneralSecurityException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        writeVersion(outputStream);
        writeRecipientTypeArgument(outputStream);
        writeRecipientBody(outputStream);
        writeMessageAuthenticationCode(outputStream);
        final byte[] bytes = outputStream.toByteArray();
        return ByteBuffer.wrap(bytes);
    }

    private void writeVersion(final OutputStream outputStream) throws IOException {
        outputStream.write(SectionIndicator.VERSION.getIndicator());
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private void writeRecipientTypeArgument(final OutputStream outputStream) throws IOException {
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        outputStream.write(RECIPIENT_TYPE.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.SPACE.getCode());
        outputStream.write(ARGUMENT.getBytes(StandardCharsets.UTF_8));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private void writeRecipientBody(final OutputStream outputStream) throws IOException {
        outputStream.write(ENCODER.encode(BODY));
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private void writeMessageAuthenticationCode(final ByteArrayOutputStream outputStream) throws IOException, GeneralSecurityException {
        outputStream.write(SectionIndicator.END.getIndicator());

        final byte[] header = outputStream.toByteArray();
        final byte[] messageAuthenticationCode = getMessageAuthenticationCode(header);

        outputStream.write(SectionSeparator.SPACE.getCode());
        final byte[] encoded = ENCODER.encode(messageAuthenticationCode);
        outputStream.write(encoded);
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private void writeInvalidMessageAuthenticationCode(final ByteArrayOutputStream outputStream) throws IOException {
        outputStream.write(SectionIndicator.END.getIndicator());

        outputStream.write(SectionSeparator.SPACE.getCode());
        final byte[] encoded = ENCODER.encode(INVALID_MAC);
        outputStream.write(encoded);
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }

    private byte[] getMessageAuthenticationCode(final byte[] header) throws GeneralSecurityException {
        final HeaderKeyProducer headerKeyProducer = HeaderKeyProducerFactory.newHeaderKeyProducer();
        final FileKey fileKey = new FileKey(FILE_KEY);
        final MacKey headerKey = headerKeyProducer.getHeaderKey(fileKey);
        final MessageAuthenticationCodeProducer producer = MessageAuthenticationCodeProducerFactory.newMessageAuthenticationCodeProducer(headerKey);
        final ByteBuffer buffer = ByteBuffer.wrap(header);
        return producer.getMessageAuthenticationCode(buffer);
    }
}
