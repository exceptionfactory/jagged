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

import com.exceptionfactory.jagged.DecryptingChannelFactory;
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.framework.crypto.ByteBufferCipherFactory;
import com.exceptionfactory.jagged.framework.crypto.StandardByteBufferCipherFactory;
import com.exceptionfactory.jagged.framework.format.PayloadKeyReader;
import com.exceptionfactory.jagged.framework.format.StandardPayloadKeyReader;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.Objects;

/**
 * Standard implementation of Decrypting Channel Factory supports reading encrypted channels
 */
public class StandardDecryptingChannelFactory implements DecryptingChannelFactory {
    private final ByteBufferCipherFactory byteBufferCipherFactory;

    /**
     * Standard Decrypting Channel Factory constructor using default Security Provider configuration
     */
    public StandardDecryptingChannelFactory() {
        byteBufferCipherFactory = new StandardByteBufferCipherFactory();
    }

    /**
     * Standard Decrypting Channel Factory constructor using specified Security Provider
     *
     * @param provider Security Provider supporting ChaCha20-Poly1305
     */
    public StandardDecryptingChannelFactory(final Provider provider) {
        Objects.requireNonNull(provider, "Provider required");
        byteBufferCipherFactory = new StandardByteBufferCipherFactory(provider);
    }

    /**
     * Create new channel that reads and decrypts from the supplied open input channel
     *
     * @param inputChannel Input Channel source containing encrypted bytes
     * @param recipientStanzaReaders Recipient Stanza Readers capable of providing the Identity to read the File Key for decryption
     * @return Readable Byte Channel
     * @throws GeneralSecurityException Thrown on recipient processing or cipher operation failures
     * @throws IOException Thrown on failures to read input channel
     */
    @Override
    public ReadableByteChannel newDecryptingChannel(
            final ReadableByteChannel inputChannel,
            final Iterable<RecipientStanzaReader> recipientStanzaReaders
    ) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(inputChannel, "Input Channel required");
        Objects.requireNonNull(recipientStanzaReaders, "Recipient Stanza Readers required");
        if (inputChannel.isOpen()) {
            final PayloadKeyReader payloadKeyReader = new StandardPayloadKeyReader();
            return new DecryptingChannel(inputChannel, recipientStanzaReaders, payloadKeyReader, byteBufferCipherFactory);
        } else {
            throw new ClosedChannelException();
        }
    }
}
