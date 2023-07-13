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

import com.exceptionfactory.jagged.RecipientStanzaWriter;

import java.util.Objects;

/**
 * Factory abstraction for returning initialized scrypt Recipient Stanza Writers from a passphrase and work factor
 */
public final class ScryptRecipientStanzaWriterFactory {
    private ScryptRecipientStanzaWriterFactory() {

    }

    /**
     * Create new scrypt Recipient Stanza Writer using a passphrase byte array and work factor
     *
     * @param passphrase Passphrase byte array
     * @param workFactor Work factor to derive scrypt N parameter
     * @return scrypt Recipient Stanza Writer
     */
    public static RecipientStanzaWriter newRecipientStanzaWriter(final byte[] passphrase, final int workFactor) {
        Objects.requireNonNull(passphrase, "Passphrase required");

        final DerivedWrapKeyProducer derivedWrapKeyProducer = new ScryptDerivedWrapKeyProducer(passphrase);
        return new ScryptRecipientStanzaWriter(derivedWrapKeyProducer, workFactor);
    }
}
