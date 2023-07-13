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
import com.exceptionfactory.jagged.framework.format.PayloadKeyWriter;
import com.exceptionfactory.jagged.framework.format.StandardPayloadKeyWriter;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Standard implementation of Encrypting Channel Factory supports writing encrypted channels
 */
public class StandardEncryptingChannelFactory implements EncryptingChannelFactory {
    /**
     * Create new channel that encrypts and writes to the supplied output channel
     *
     * @param outputChannel Output Channel destination for encrypted bytes
     * @param recipientStanzaWriters One or more Recipient Stanza Writers for intended recipients
     * @return Writable Byte Channel
     * @throws IOException Thrown on failures to write Channel or Recipient Stanzas
      @throws GeneralSecurityException Thrown on recipient writing or cipher operation failures
     */
    @Override
    public WritableByteChannel newEncryptingChannel(
            final WritableByteChannel outputChannel,
            final Iterable<RecipientStanzaWriter> recipientStanzaWriters
    ) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(outputChannel, "Output Channel required");
        Objects.requireNonNull(recipientStanzaWriters, "Recipient Stanza Writers required");

        if (outputChannel.isOpen()) {
            final PayloadKeyWriter payloadKeyWriter = new StandardPayloadKeyWriter();
            return new EncryptingChannel(outputChannel, recipientStanzaWriters, payloadKeyWriter);
        } else {
            throw new ClosedChannelException();
        }
    }
}
