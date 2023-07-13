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

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanzaReader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Abstraction responsible for reading and verifying File Header before returning File Key
 */
interface FileKeyReader {
    /**
     * Read File Key from File Header buffer using provided Recipient Stanza Reader
     *
     * @param buffer File Header buffer
     * @param recipientStanzaReader Recipient Stanza Reader
     * @return File Key
     * @throws IOException Thrown on failures to read File Header
     * @throws GeneralSecurityException Thrown on failures to read File Key or verify File Header
     */
    FileKey readFileKey(ByteBuffer buffer, RecipientStanzaReader recipientStanzaReader) throws IOException, GeneralSecurityException;
}
