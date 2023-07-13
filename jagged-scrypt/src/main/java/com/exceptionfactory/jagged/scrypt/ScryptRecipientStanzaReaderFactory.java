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
package com.exceptionfactory.jagged.scrypt;

import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;

import java.security.GeneralSecurityException;

/**
 * Factory abstraction for returning initialized scrypt Recipient Stanza Readers from a passphrase
 */
public final class ScryptRecipientStanzaReaderFactory {
    private ScryptRecipientStanzaReaderFactory() {

    }

    /**
     * Create new scrypt Recipient Stanza Reader using a passphrase byte array
     *
     * @param passphrase Passphrase byte array
     * @return scrypt Recipient Stanza Reader
     * @throws GeneralSecurityException Thrown on failures to read passphrase or required parameters
     */
    public static RecipientStanzaReader newRecipientStanzaReader(final byte[] passphrase) throws GeneralSecurityException {
        if (passphrase == null) {
            throw new UnsupportedRecipientStanzaException("Passphrase required");
        }
        final DerivedWrapKeyProducer derivedWrapKeyProducer = new ScryptDerivedWrapKeyProducer(passphrase);
        return new ScryptRecipientStanzaReader(derivedWrapKeyProducer);
    }
}
