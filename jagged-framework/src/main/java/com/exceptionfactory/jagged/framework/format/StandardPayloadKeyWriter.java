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
import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.HeaderKeyProducer;
import com.exceptionfactory.jagged.framework.crypto.HeaderKeyProducerFactory;
import com.exceptionfactory.jagged.framework.crypto.MacKey;
import com.exceptionfactory.jagged.framework.crypto.MessageAuthenticationCodeProducer;
import com.exceptionfactory.jagged.framework.crypto.MessageAuthenticationCodeProducerFactory;
import com.exceptionfactory.jagged.framework.crypto.PayloadKeyProducer;
import com.exceptionfactory.jagged.framework.crypto.PayloadKeyProducerFactory;
import com.exceptionfactory.jagged.framework.crypto.PayloadNonceKey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Standard implementation of Payload Key Writer generates a File Key and serializes File Header then returns derived Payload Key
 */
public class StandardPayloadKeyWriter implements PayloadKeyWriter {
    /**
     * Write File Header to buffer after generating a File Key and return derived Payload Key
     *
     * @param buffer Byte Buffer with sufficient capacity for serialized File Header should support at least 128 bytes
     * @param recipientStanzaWriters Recipient Stanza Writers
     * @return Derived Payload Cipher Key for encryption operations
     * @throws GeneralSecurityException Thrown on cipher operation failures
     * @throws IOException Thrown on serialization failures
     */
    @Override
    public CipherKey writeFileHeader(final ByteBuffer buffer, final Iterable<RecipientStanzaWriter> recipientStanzaWriters) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(buffer, "Buffer required");
        Objects.requireNonNull(recipientStanzaWriters, "Recipient Stanza Writers required");

        final FileKey fileKey = new FileKey();
        final List<RecipientStanza> recipientStanzas = writeRecipientStanzas(recipientStanzaWriters, fileKey);
        final ByteBuffer fileHeader = writeFileHeader(recipientStanzas, fileKey);
        if (buffer.remaining() < fileHeader.remaining()) {
            final String message = String.format("Buffer bytes remaining [%d] less than required File Header bytes [%d]", buffer.remaining(), fileHeader.remaining());
            throw new PayloadException(message);
        }
        buffer.put(fileHeader);

        final PayloadNonceKey payloadNonceKey = new PayloadNonceKey();
        final byte[] payloadNonceKeyEncoded = payloadNonceKey.getEncoded();
        if (buffer.remaining() < payloadNonceKeyEncoded.length) {
            final String message = String.format("Buffer bytes remaining [%d] less than required Payload Nonce bytes [%d]", buffer.remaining(), payloadNonceKeyEncoded.length);
            throw new PayloadException(message);
        }
        buffer.put(payloadNonceKeyEncoded);

        final PayloadKeyProducer payloadKeyProducer = PayloadKeyProducerFactory.newPayloadKeyProducer();
        final CipherKey payloadKey = payloadKeyProducer.getPayloadKey(fileKey, payloadNonceKey);

        fileKey.destroy();
        return payloadKey;
    }

    private List<RecipientStanza> writeRecipientStanzas(final Iterable<RecipientStanzaWriter> recipientStanzaWriters, final FileKey fileKey) throws GeneralSecurityException {
        final List<RecipientStanza> collectedRecipientStanzas = new ArrayList<>();
        for (final RecipientStanzaWriter recipientStanzaWriter : recipientStanzaWriters) {
            final Iterable<RecipientStanza> recipientStanzas = recipientStanzaWriter.getRecipientStanzas(fileKey);
            recipientStanzas.forEach(collectedRecipientStanzas::add);
        }
        return collectedRecipientStanzas;
    }

    private ByteBuffer writeFileHeader(final List<RecipientStanza> recipientStanzas, final FileKey fileKey) throws GeneralSecurityException, IOException {
        final FileHeaderWriter fileHeaderWriter = getFileHeaderWriter(fileKey);
        return fileHeaderWriter.writeRecipientStanzas(recipientStanzas);
    }

    private FileHeaderWriter getFileHeaderWriter(final FileKey fileKey) throws GeneralSecurityException {
        final HeaderKeyProducer headerKeyProducer = HeaderKeyProducerFactory.newHeaderKeyProducer();
        final MacKey headerKey = headerKeyProducer.getHeaderKey(fileKey);
        final MessageAuthenticationCodeProducer messageAuthenticationCodeProducer = MessageAuthenticationCodeProducerFactory.newMessageAuthenticationCodeProducer(headerKey);
        return new AuthenticatedStandardFileHeaderWriter(messageAuthenticationCodeProducer);
    }
}
