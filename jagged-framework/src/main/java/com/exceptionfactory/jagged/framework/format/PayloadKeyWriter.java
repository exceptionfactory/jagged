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

import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Abstraction responsible for writing File Header and returning a Payload Key from a generated File Key
 */
public interface PayloadKeyWriter {
    /**
     * Write File Header to buffer after generating a File Key and return derived Payload Key
     *
     * @param buffer Byte Buffer with sufficient capacity for serialized File Header should support at least 128 bytes
     * @param recipientStanzaWriters Recipient Stanza Writers
     * @return Derived Payload Cipher Key for encryption operations
     * @throws GeneralSecurityException Thrown on cipher operation failures
     * @throws IOException Thrown on serialization failures
     */
    CipherKey writeFileHeader(ByteBuffer buffer, Iterable<RecipientStanzaWriter> recipientStanzaWriters) throws GeneralSecurityException, IOException;
}
