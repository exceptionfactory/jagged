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
package com.exceptionfactory.jagged.framework.stream;

import com.exceptionfactory.jagged.EncryptingChannelFactory;
import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.crypto.ByteBufferCipherFactory;
import com.exceptionfactory.jagged.framework.crypto.StandardByteBufferCipherFactory;
import com.exceptionfactory.jagged.framework.format.PayloadKeyWriter;
import com.exceptionfactory.jagged.framework.format.StandardPayloadKeyWriter;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.Objects;

/**
 * Standard implementation of Encrypting Channel Factory supports writing encrypted channels
 */
public class StandardEncryptingChannelFactory implements EncryptingChannelFactory {
    private final ByteBufferCipherFactory byteBufferCipherFactory;

    /**
     * Standard Encrypting Channel Factory constructor using default Security Provider configuration
     */
    public StandardEncryptingChannelFactory() {
        byteBufferCipherFactory = new StandardByteBufferCipherFactory();
    }

    /**
     * Standard Encrypting Channel Factory constructor using specified Security Provider
     *
     * @param provider Security Provider supporting ChaCha20-Poly1305
     */
    public StandardEncryptingChannelFactory(final Provider provider) {
        Objects.requireNonNull(provider, "Provider required");
        byteBufferCipherFactory = new StandardByteBufferCipherFactory(provider);
    }

    /**
     * Create new channel that encrypts and writes to the supplied output channel
     *
     * @param outputChannel Output Channel destination for encrypted bytes
     * @param recipientStanzaWriters One or more Recipient Stanza Writers for intended recipients
     * @return Writable Byte Channel
     * @throws GeneralSecurityException Thrown on recipient writing or cipher operation failures
     * @throws IOException Thrown on failures to write Channel or Recipient Stanzas
     */
    @Override
    public WritableByteChannel newEncryptingChannel(
            final WritableByteChannel outputChannel,
            final Iterable<RecipientStanzaWriter> recipientStanzaWriters
    ) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(outputChannel, "Output Channel required");
        Objects.requireNonNull(recipientStanzaWriters, "Recipient Stanza Writers required");

        if (outputChannel.isOpen()) {
            final PayloadKeyWriter payloadKeyWriter = new StandardPayloadKeyWriter();
            return new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter, byteBufferCipherFactory);
        } else {
            throw new ClosedChannelException();
        }
    }
}
