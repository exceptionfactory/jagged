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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * File Header Reader serializes Recipient Stanzas according to standard age encryption specifications
 */
interface FileHeaderWriter {
    /**
     * Write Recipient Stanzas along with formatted age header elements
     *
     * @param recipientStanzas Recipient Stanzas
     * @return Byte Buffer containing serialized age header
     * @throws GeneralSecurityException Thrown on failures to run cryptographic operations while serializing header
     * @throws IOException Thrown on failures to write Recipient Stanzas
     */
    ByteBuffer writeRecipientStanzas(Iterable<RecipientStanza> recipientStanzas) throws GeneralSecurityException, IOException;
}
