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
package com.exceptionfactory.jagged.x25519;

import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.bech32.Bech32;
import com.exceptionfactory.jagged.bech32.Bech32Address;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Factory abstraction for returning initialized X25519 Recipient Stanza Writers from a Bech32 encoded Public Key
 */
public final class X25519RecipientStanzaWriterFactory {
    private X25519RecipientStanzaWriterFactory() {

    }

    /**
     * Create new X25519 Recipient Stanza Writer using Bech32 encoded key
     *
     * @param encodedPublicKey Bech32 encoded key starting with age
     * @return X25519 Recipient Stanza Writer
     * @throws GeneralSecurityException Thrown on failures to process encoded key or prepare supporting components
     */
    public static RecipientStanzaWriter newRecipientStanzaWriter(final CharSequence encodedPublicKey) throws GeneralSecurityException {
        Objects.requireNonNull(encodedPublicKey, "Encoded Public Key required");
        final Bech32.Decoder decoder = Bech32.getDecoder();
        final Bech32Address address = decoder.decode(encodedPublicKey);
        final CharSequence humanReadablePart = address.getHumanReadablePart();
        if (RecipientIndicator.PUBLIC_KEY_HUMAN_READABLE_PART.getIndicator().contentEquals(humanReadablePart)) {
            final byte[] publicKeyEncoded = address.getData();
            final RecipientKeyFactory recipientKeyFactory = new StandardRecipientKeyFactory();
            final PublicKey recipientPublicKey = recipientKeyFactory.getPublicKey(publicKeyEncoded);
            final SharedWrapKeyProducer sharedWrapKeyProducer = new X25519SharedWrapKeyProducer(recipientPublicKey);
            return new X25519RecipientStanzaWriter(recipientPublicKey, recipientKeyFactory, sharedWrapKeyProducer);
        } else {
            final String message = String.format("Public Key Human-Readable Part not matched [%s]", humanReadablePart);
            throw new InvalidKeyException(message);
        }
    }
}
