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
 * Unsupported Recipient Stanza Exception indicating incorrect formatting or no matched Recipient Stanza found in age file header
 */
public class UnsupportedRecipientStanzaException extends GeneralSecurityException {
    /**
     * Unsupported Recipient Stanza Exception constructor with message providing additional details
     *
     * @param message Message providing additional details
     */
    public UnsupportedRecipientStanzaException(final String message) {
        super(message);
    }
}
