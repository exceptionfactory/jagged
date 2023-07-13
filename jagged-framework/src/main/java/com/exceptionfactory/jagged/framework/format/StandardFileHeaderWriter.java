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

import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64OutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Standard File Header Writer serializes Recipient Stanzas with standard age encryption header and without Message Authentication Code footer
 */
class StandardFileHeaderWriter implements FileHeaderWriter {
    private static final int INITIAL_BUFFER_SIZE = 128;

    private static final Charset STANDARD_CHARACTER_SET = StandardCharsets.UTF_8;

    /**
     * Write Recipient Stanzas without Message Authentication Code footer and return serialized bytes
     *
     * @param recipientStanzas Recipient Stanzas
     * @return Serialized bytes
     * @throws IOException Thrown on failures writing serialized Recipient Stanzas
     * @throws GeneralSecurityException Thrown on failures for security operations
     */
    @Override
    public ByteBuffer writeRecipientStanzas(final Iterable<RecipientStanza> recipientStanzas) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(recipientStanzas, "Recipient Stanzas required");

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(INITIAL_BUFFER_SIZE)) {
            writeRecipientStanzas(outputStream, recipientStanzas);
            final byte[] serialized = outputStream.toByteArray();
            return ByteBuffer.wrap(serialized);
        }
    }

    private void writeRecipientStanzas(final ByteArrayOutputStream outputStream, final Iterable<RecipientStanza> recipientStanzas) throws IOException {
        outputStream.write(SectionIndicator.VERSION.getIndicator());
        outputStream.write(SectionSeparator.LINE_FEED.getCode());

        for (final RecipientStanza recipientStanza : recipientStanzas) {
            writeRecipientStanza(outputStream, recipientStanza);
        }

        outputStream.write(SectionIndicator.END.getIndicator());
    }

    private void writeRecipientStanza(final ByteArrayOutputStream outputStream, final RecipientStanza recipientStanza) throws IOException {
        outputStream.write(SectionIndicator.STANZA.getIndicator());
        final byte[] typeBytes = recipientStanza.getType().getBytes(STANDARD_CHARACTER_SET);
        outputStream.write(typeBytes);

        for (final String argument : recipientStanza.getArguments()) {
            outputStream.write(SectionSeparator.SPACE.getCode());
            final byte[] argumentBytes = argument.getBytes(STANDARD_CHARACTER_SET);
            outputStream.write(argumentBytes);
        }

        outputStream.write(SectionSeparator.LINE_FEED.getCode());

        // Closing encoding Output Stream writes final bytes without impact subsequent operations on ByteArrayOutputStream
        try (CanonicalBase64OutputStream encodingOutputStream = new CanonicalBase64OutputStream(outputStream)) {
            final byte[] body = recipientStanza.getBody();
            encodingOutputStream.write(body);
        }
        outputStream.write(SectionSeparator.LINE_FEED.getCode());
    }
}
