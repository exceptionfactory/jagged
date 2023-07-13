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

import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Abstraction responsible for reading File Header and deriving Payload Key from File Key after header verification
 */
public interface PayloadKeyReader {
    /**
     * Get Payload Key from File Header buffer using provided Recipient Stanza Readers to read File Key
     *
     * @param buffer File Header buffer
     * @param recipientStanzaReaders Recipient Stanza Readers
     * @return Payload Key
     * @throws IOException Thrown on failures to read File Header
     * @throws GeneralSecurityException Thrown on failures to derive Payload Key
     */
    CipherKey getPayloadKey(ByteBuffer buffer, Iterable<RecipientStanzaReader> recipientStanzaReaders) throws IOException, GeneralSecurityException;
}
