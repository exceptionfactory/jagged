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
package com.exceptionfactory.jagged;

import java.io.IOException;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;

/**
 * Abstraction for creating writable Channels supporting streaming age encryption
 */
public interface EncryptingChannelFactory {
    /**
     * Create new channel that encrypts and writes to the supplied output channel
     *
     * @param outputChannel Output Channel destination for encrypted bytes
     * @param recipientStanzaWriters One or more Recipient Stanza Writers for intended recipients
     * @return Writable Byte Channel for encrypted bytes
     * @throws GeneralSecurityException Thrown on failures writing recipients or performing cipher operations
     * @throws IOException Thrown on failures to write Channel or Recipient Stanzas
     */
    WritableByteChannel newEncryptingChannel(
            WritableByteChannel outputChannel,
            Iterable<RecipientStanzaWriter> recipientStanzaWriters
    ) throws GeneralSecurityException, IOException;
}
