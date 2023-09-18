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
import com.exceptionfactory.jagged.framework.crypto.PayloadKeyProducer;
import com.exceptionfactory.jagged.framework.crypto.PayloadKeyProducerFactory;
import com.exceptionfactory.jagged.framework.crypto.PayloadNonceKey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Standard implementation of Payload Key Reader
 */
public class StandardPayloadKeyReader implements PayloadKeyReader {
    private static final int NONCE_LENGTH = 16;

    private final FileKeyReader fileKeyReader;

    private final PayloadKeyProducer payloadKeyProducer = PayloadKeyProducerFactory.newPayloadKeyProducer();

    /**
     * Standard Payload Key Reader constructor with Standard File Key Reader
     */
    public StandardPayloadKeyReader() {
        this(new StandardFileKeyReader());
    }

    /**
     * Standard Payload Key Reader with configurable File Key Reader
     *
     * @param fileKeyReader File Key Reader
     */
    StandardPayloadKeyReader(final FileKeyReader fileKeyReader) {
        this.fileKeyReader = fileKeyReader;
    }

    /**
     * Get Payload Key from File Header buffer using provided Recipient Stanza Readers to read File Key
     *
     * @param buffer File Header buffer
     * @param recipientStanzaReaders Recipient Stanza Readers
     * @return Payload Key
     * @throws GeneralSecurityException Thrown on failures to derive Payload Key
     * @throws IOException Thrown on failures to read File Header
     */
    @Override
    public CipherKey getPayloadKey(final ByteBuffer buffer, final Iterable<RecipientStanzaReader> recipientStanzaReaders) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(buffer, "Buffer required");
        Objects.requireNonNull(recipientStanzaReaders, "Recipient Stanza Readers required");

        final FileKey fileKey = readFileKey(buffer, recipientStanzaReaders);
        final PayloadNonceKey payloadNonceKey = readPayloadNonceKey(buffer);
        final CipherKey payloadKey = payloadKeyProducer.getPayloadKey(fileKey, payloadNonceKey);

        fileKey.destroy();
        return payloadKey;
    }

    private FileKey readFileKey(final ByteBuffer buffer, final Iterable<RecipientStanzaReader> recipientStanzaReaders) throws GeneralSecurityException, IOException {
        final List<GeneralSecurityException> exceptions = new ArrayList<>();

        FileKey fileKey = null;
        buffer.mark();
        for (final RecipientStanzaReader recipientStanzaReader : recipientStanzaReaders) {
            try {
                fileKey = fileKeyReader.readFileKey(buffer, recipientStanzaReader);
                break;
            } catch (final GeneralSecurityException e) {
                exceptions.add(e);
                buffer.reset();
            }
        }

        if (fileKey == null) {
            if (exceptions.size() == 1) {
                throw exceptions.get(0);
            }
            final UnsupportedRecipientStanzaException exception = new UnsupportedRecipientStanzaException("Supported Recipient Stanza not found");
            exceptions.forEach(exception::addSuppressed);
            throw exception;
        }
        return fileKey;
    }

    private PayloadNonceKey readPayloadNonceKey(final ByteBuffer buffer) throws InvalidParameterSpecException {
        if (buffer.remaining() < NONCE_LENGTH) {
            throw new InvalidParameterSpecException("Payload Nonce not found");
        }

        final byte[] nonce = new byte[NONCE_LENGTH];
        buffer.get(nonce);
        return new PayloadNonceKey(nonce);
    }
}
