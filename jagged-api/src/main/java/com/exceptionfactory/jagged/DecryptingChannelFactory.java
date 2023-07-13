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
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;

/**
 * Abstraction for creating readable Channels supporting streaming age decryption
 */
public interface DecryptingChannelFactory {
    /**
     * Create new channel that reads and decrypts from the supplied input channel
     *
     * @param inputChannel Input Channel source containing encrypted bytes
     * @param recipientStanzaReaders Recipient Stanza Readers capable of providing the Identity to read the File Key for decryption
     * @return Readable Byte Channel containing decrypted bytes
     * @throws IOException Thrown on failures to read Channel or Recipient Stanzas
     * @throws GeneralSecurityException Thrown on failures while processing recipients or performing cipher operations
     */
    ReadableByteChannel newDecryptingChannel(ReadableByteChannel inputChannel, Iterable<RecipientStanzaReader> recipientStanzaReaders) throws IOException, GeneralSecurityException;
}
