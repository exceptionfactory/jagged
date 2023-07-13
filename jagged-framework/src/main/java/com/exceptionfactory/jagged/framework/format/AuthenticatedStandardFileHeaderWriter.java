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
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import com.exceptionfactory.jagged.framework.crypto.MessageAuthenticationCodeProducer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Authenticated extension of File Header Writer that calculates a Message Authentication Code and appends to the serialized buffer
 */
class AuthenticatedStandardFileHeaderWriter extends StandardFileHeaderWriter {
    /** Encoded Message Authentication Code plus preceding space and trailing line feed characters */
    private static final int MESSAGE_AUTHENTICATION_CODE_FOOTER_LENGTH = 45;

    private static final byte SPACE_SEPARATOR = 32;

    private static final byte LINE_FEED = 10;

    private static final CanonicalBase64.Encoder ENCODER = CanonicalBase64.getEncoder();

    private final MessageAuthenticationCodeProducer messageAuthenticationCodeProducer;

    AuthenticatedStandardFileHeaderWriter(final MessageAuthenticationCodeProducer messageAuthenticationCodeProducer) {
        this.messageAuthenticationCodeProducer = Objects.requireNonNull(messageAuthenticationCodeProducer, "Authentication Code Producer required");
    }

    /**
     * Write Recipient Stanzas with Message Authentication Code footer and return serialized bytes
     *
     * @param recipientStanzas Recipient Stanzas
     * @return Serialized File Header with Message Authentication Code after Footer
     * @throws IOException Thrown on failures writing serialized Recipient Stanzas
     */
    @Override
    public ByteBuffer writeRecipientStanzas(final Iterable<RecipientStanza> recipientStanzas) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(recipientStanzas, "Recipient Stanzas required");
        final ByteBuffer serialized = super.writeRecipientStanzas(recipientStanzas);

        final byte[] messageAuthenticationCode = messageAuthenticationCodeProducer.getMessageAuthenticationCode(serialized);
        serialized.rewind();

        final int capacity = serialized.capacity() + MESSAGE_AUTHENTICATION_CODE_FOOTER_LENGTH;
        final ByteBuffer authenticated = ByteBuffer.allocate(capacity);

        authenticated.put(serialized);
        authenticated.put(SPACE_SEPARATOR);

        final byte[] messageAuthenticationCodeEncoded = ENCODER.encode(messageAuthenticationCode);
        authenticated.put(messageAuthenticationCodeEncoded);

        authenticated.put(LINE_FEED);
        authenticated.flip();
        return authenticated;
    }
}
