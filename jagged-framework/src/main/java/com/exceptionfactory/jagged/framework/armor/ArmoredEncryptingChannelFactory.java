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
package com.exceptionfactory.jagged.framework.armor;

import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.stream.StandardEncryptingChannelFactory;

import java.io.IOException;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.Provider;

/**
 * ASCII Armored implementation of Encrypting Channel Factory supports writing encrypted channels with Base64 wrapping
 */
public class ArmoredEncryptingChannelFactory extends StandardEncryptingChannelFactory {
    /**
     * Armored Encrypting Channel Factory constructor using default Security Provider configuration
     */
    public ArmoredEncryptingChannelFactory() {
        super();
    }

    /**
     * Armored Encrypting Channel Factory constructor using specified Security Provider
     *
     * @param provider Security Provider supporting ChaCha20-Poly1305
     */
    public ArmoredEncryptingChannelFactory(final Provider provider) {
        super(provider);
    }

    /**
     * Create new channel that encrypts and writes to the supplied output channel with ASCII Armored Base64 wrapping
     *
     * @param outputChannel Output Channel destination for encrypted bytes
     * @param recipientStanzaWriters One or more Recipient Stanza Writers for intended recipients
     * @return Writable Byte Channel with ASCII Armored Base64 wrapping
     * @throws IOException Thrown on failures to write Channel or Recipient Stanzas
      @throws GeneralSecurityException Thrown on recipient writing or cipher operation failures
     */
    @Override
    public WritableByteChannel newEncryptingChannel(
            final WritableByteChannel outputChannel,
            final Iterable<RecipientStanzaWriter> recipientStanzaWriters
    ) throws IOException, GeneralSecurityException {
        return super.newEncryptingChannel(new ArmoredWritableByteChannel(outputChannel), recipientStanzaWriters);
    }
}
