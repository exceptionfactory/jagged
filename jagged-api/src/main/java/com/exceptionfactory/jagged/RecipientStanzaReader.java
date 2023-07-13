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

import java.security.GeneralSecurityException;

/**
 * Identity abstraction for reading Recipient Stanzas and returning a File Key
 */
public interface RecipientStanzaReader {
    /**
     * Get File Key reads one or more Recipient Stanzas and return a File Key of 16 bytes
     *
     * @param recipientStanzas One or more Recipient Stanzas parsed from the age file header
     * @return File Key decrypted from matching Recipient Stanza in age file header
     * @throws GeneralSecurityException Thrown on failure to decrypt File Key or process Recipient Stanzas
     */
    FileKey getFileKey(Iterable<RecipientStanza> recipientStanzas) throws GeneralSecurityException;
}
