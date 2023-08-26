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

import java.util.Objects;

/**
 * Standard implementation of age-encryption File Header
 */
class StandardFileHeader implements FileHeader {
    private final Iterable<RecipientStanza> recipientStanzas;

    private final byte[] messageAuthenticationCode;

    StandardFileHeader(final Iterable<RecipientStanza> recipientStanzas, final byte[] messageAuthenticationCode) {
        this.recipientStanzas = Objects.requireNonNull(recipientStanzas, "Recipient Stanzas required");
        this.messageAuthenticationCode = Objects.requireNonNull(messageAuthenticationCode, "Message Authentication Code required");
    }

    @Override
    public Iterable<RecipientStanza> getRecipientStanzas() {
        return recipientStanzas;
    }

    @Override
    public byte[] getMessageAuthenticationCode() {
        return messageAuthenticationCode.clone();
    }
}
