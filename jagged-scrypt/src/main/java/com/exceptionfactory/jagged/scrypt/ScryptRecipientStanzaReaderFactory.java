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
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptor;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptorFactory;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.Objects;

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
        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory();
        return newRecipientStanzaReader(fileKeyDecryptorFactory, passphrase);
    }

    /**
     * Create new scrypt Recipient Stanza Reader using a passphrase byte array and specified Security Provider
     *
     * @param passphrase Passphrase byte array
     * @param provider Security Provider for algorithm implementation resolution
     * @return scrypt Recipient Stanza Reader
     * @throws GeneralSecurityException Thrown on failures to read passphrase or required parameters
     */
    public static RecipientStanzaReader newRecipientStanzaReader(final byte[] passphrase, final Provider provider) throws GeneralSecurityException {
        Objects.requireNonNull(provider, "Provider required");
        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory(provider);
        return newRecipientStanzaReader(fileKeyDecryptorFactory, passphrase);
    }

    private static RecipientStanzaReader newRecipientStanzaReader(final FileKeyDecryptorFactory fileKeyDecryptorFactory, final byte[] passphrase) throws UnsupportedRecipientStanzaException {
        final DerivedWrapKeyProducer derivedWrapKeyProducer = getDerivedWrapKeyProducer(passphrase);
        final FileKeyDecryptor fileKeyDecryptor = fileKeyDecryptorFactory.newFileKeyDecryptor();
        return new ScryptRecipientStanzaReader(derivedWrapKeyProducer, fileKeyDecryptor);
    }

    private static DerivedWrapKeyProducer getDerivedWrapKeyProducer(final byte[] passphrase) throws UnsupportedRecipientStanzaException {
        if (passphrase == null) {
            throw new UnsupportedRecipientStanzaException("Passphrase required");
        }
        return new ScryptDerivedWrapKeyProducer(passphrase);
    }
}
