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

import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.bech32.Bech32;
import com.exceptionfactory.jagged.bech32.Bech32Address;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Factory abstraction for returning initialized X25519 Recipient Stanza Readers from a Bech32 encoded Private Key
 */
public final class X25519RecipientStanzaReaderFactory {
    private static final BasePointPublicKey BASE_POINT_PUBLIC_KEY = new BasePointPublicKey();

    private X25519RecipientStanzaReaderFactory() {

    }

    /**
     * Create new X25519 Recipient Stanza Reader using Bech32 encoded key
     *
     * @param encodedPrivateKey Bech32 encoded key starting with AGE-SECRET-KEY
     * @return X25519 Recipient Stanza Reader
     * @throws GeneralSecurityException Thrown on failures to process encoded key or prepare supporting components
     */
    public static RecipientStanzaReader newRecipientStanzaReader(final CharSequence encodedPrivateKey) throws GeneralSecurityException {
        Objects.requireNonNull(encodedPrivateKey, "Encoded Private Key required");
        final Bech32.Decoder decoder = Bech32.getDecoder();
        final Bech32Address address = decoder.decode(encodedPrivateKey);
        final CharSequence humanReadablePart = address.getHumanReadablePart();
        if (IdentityIndicator.PRIVATE_KEY_HUMAN_READABLE_PART.getIndicator().contentEquals(humanReadablePart)) {
            final byte[] privateKeyEncoded = address.getData();
            final RecipientKeyFactory recipientKeyFactory = new StandardRecipientKeyFactory();
            final PrivateKey privateKey = recipientKeyFactory.getPrivateKey(privateKeyEncoded);
            return newRecipientStanzaReader(privateKey, recipientKeyFactory);
        } else {
            final String message = String.format("Private Key Human-Readable Part not matched [%s]", humanReadablePart);
            throw new InvalidKeyException(message);
        }
    }

    private static RecipientStanzaReader newRecipientStanzaReader(final PrivateKey privateKey, final RecipientKeyFactory recipientKeyFactory) throws GeneralSecurityException {
        final SharedSecretKeyProducer sharedSecretKeyProducer = new X25519SharedSecretKeyProducer(privateKey);
        final SharedWrapKeyProducer sharedWrapKeyProducer = getWrapKeyProducer(sharedSecretKeyProducer, recipientKeyFactory);
        return new X25519RecipientStanzaReader(recipientKeyFactory, sharedSecretKeyProducer, sharedWrapKeyProducer);
    }

    private static SharedWrapKeyProducer getWrapKeyProducer(final SharedSecretKeyProducer sharedSecretKeyProducer, final RecipientKeyFactory recipientKeyFactory) throws GeneralSecurityException {
        final PublicKey basePointPublicKey = recipientKeyFactory.getPublicKey(BASE_POINT_PUBLIC_KEY.getEncoded());
        final SharedSecretKey basePointSharedSecretKey = sharedSecretKeyProducer.getSharedSecretKey(basePointPublicKey);
        final byte[] basePointSharedSecretKeyEncoded = basePointSharedSecretKey.getEncoded();
        final PublicKey recipientPublicKey = recipientKeyFactory.getPublicKey(basePointSharedSecretKeyEncoded);
        return new X25519SharedWrapKeyProducer(recipientPublicKey);
    }
}
