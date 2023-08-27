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
import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.framework.crypto.HeaderKeyProducer;
import com.exceptionfactory.jagged.framework.crypto.HeaderKeyProducerFactory;
import com.exceptionfactory.jagged.framework.crypto.MacKey;
import com.exceptionfactory.jagged.framework.crypto.MessageAuthenticationCodeProducer;
import com.exceptionfactory.jagged.framework.crypto.MessageAuthenticationCodeProducerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.Objects;

/**
 * Standard implementation of File Key Reader attempts to read File Key using Recipient Stanza Reader and verify header
 */
class StandardFileKeyReader implements FileKeyReader {
    private static final FileHeaderReader FILE_HEADER_READER = new StandardFileHeaderReader();

    private static final HeaderKeyProducer HEADER_KEY_PRODUCER = HeaderKeyProducerFactory.newHeaderKeyProducer();

    /**
     * Read File Key from File Header buffer using provided Recipient Stanza Reader and verify Message Authentication Code using derived Header Key
     *
     * @param buffer File Header buffer with capacity limiting the number and size of possible Recipient Stanzas
     * @param recipientStanzaReader Recipient Stanza Reader
     * @return File Key
     * @throws GeneralSecurityException Thrown on failures to read File Key or verify File Header
     * @throws IOException Thrown on failures to read File Header
     */
    @Override
    public FileKey readFileKey(final ByteBuffer buffer, final RecipientStanzaReader recipientStanzaReader) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(buffer, "Buffer required");
        Objects.requireNonNull(recipientStanzaReader, "Recipient Stanza Reader required");

        final FileHeader fileHeader = FILE_HEADER_READER.getFileHeader(buffer);
        final Iterable<RecipientStanza> recipientStanzas = fileHeader.getRecipientStanzas();
        final FileKey fileKey = recipientStanzaReader.getFileKey(recipientStanzas);
        if (fileKey == null) {
            throw new InvalidKeyException("Recipient Stanza Reader returned null File Key");
        }

        if (isHeaderVerified(fileHeader, fileKey)) {
            return fileKey;
        } else {
            throw new SignatureException("Header Message Authentication Code not verified");
        }
    }

    private boolean isHeaderVerified(final FileHeader fileHeader, final FileKey fileKey) throws GeneralSecurityException, IOException {
        final FileHeaderWriter fileHeaderWriter = new StandardFileHeaderWriter();
        final Iterable<RecipientStanza> recipientStanzas = fileHeader.getRecipientStanzas();
        final ByteBuffer fileHeaderBuffer = fileHeaderWriter.writeRecipientStanzas(recipientStanzas);

        final MacKey headerKey = HEADER_KEY_PRODUCER.getHeaderKey(fileKey);
        final MessageAuthenticationCodeProducer producer = MessageAuthenticationCodeProducerFactory.newMessageAuthenticationCodeProducer(headerKey);
        final byte[] messageAuthenticationCode = producer.getMessageAuthenticationCode(fileHeaderBuffer);

        return MessageDigest.isEqual(messageAuthenticationCode, fileHeader.getMessageAuthenticationCode());
    }
}
