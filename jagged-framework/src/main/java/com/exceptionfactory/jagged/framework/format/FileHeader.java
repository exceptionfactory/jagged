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

/**
 * File Header containing Recipient Stanzas and Message Authentication Code from age-encryption header
 */
interface FileHeader {
    /**
     * Get Recipient Stanzas read from File Header
     *
     * @return Recipient Stanzas
     */
    Iterable<RecipientStanza> getRecipientStanzas();

    /**
     * Get Message Authentication Code bytes
     *
     * @return Message Authentication Code bytes
     */
    byte[] getMessageAuthenticationCode();
}
