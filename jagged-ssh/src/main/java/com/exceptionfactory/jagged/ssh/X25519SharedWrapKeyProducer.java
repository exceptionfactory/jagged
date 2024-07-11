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
package com.exceptionfactory.jagged.ssh;

import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.HashedDerivedKeyProducer;
import com.exceptionfactory.jagged.framework.crypto.SharedSaltKey;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Standard implementation with HKDF-SHA-256 for File Key decryption using X25519 key derived from SSH Ed25519 key
 */
class X25519SharedWrapKeyProducer extends HashedDerivedKeyProducer implements SharedWrapKeyProducer {
    private static final byte[] KEY_INFORMATION = SshEd25519RecipientIndicator.KEY_INFORMATION.getIndicator().getBytes(StandardCharsets.UTF_8);

    /** Public Coordinate Length after ASN.1 with DER header */
    private static final int PUBLIC_COORDINATE_LENGTH = EllipticCurveKeyType.X25519.getKeyLength();

    private static final int SHARED_SALT_KEY_LENGTH = 64;

    private final byte[] recipientPublicCoordinate;

    X25519SharedWrapKeyProducer(final PublicKey recipientPublicKey) {
        this.recipientPublicCoordinate = getPublicCoordinate(Objects.requireNonNull(recipientPublicKey, "Recipient Public Key required"));
    }

    /**
     * Get Wrap Cipher Key using Shared Secret Key with HKDF-SHA-256 derivation
     *
     * @param sharedSecretKey Shared Secret Key
     * @param ephemeralPublicKey Ephemeral Public Key from Recipient Stanza Arguments
     * @return Wrap Cipher Key for decrypting wrapped File Key
     * @throws GeneralSecurityException Thrown on failure to derive wrap key
     */
    @Override
    public CipherKey getWrapKey(final SharedSecretKey sharedSecretKey, final PublicKey ephemeralPublicKey) throws GeneralSecurityException {
        Objects.requireNonNull(sharedSecretKey, "Shared Secret Key required");
        Objects.requireNonNull(ephemeralPublicKey, "Ephemeral Public Key required");
        final SharedSaltKey sharedSaltKey = getSharedSaltKey(ephemeralPublicKey);
        final byte[] wrapKey = getDerivedKey(sharedSecretKey, sharedSaltKey, KEY_INFORMATION);
        return new CipherKey(wrapKey);
    }

    private SharedSaltKey getSharedSaltKey(final PublicKey ephemeralPublicKey) {
        final byte[] saltKey = new byte[SHARED_SALT_KEY_LENGTH];
        final byte[] ephemeralPublicCoordinate = getPublicCoordinate(ephemeralPublicKey);
        System.arraycopy(ephemeralPublicCoordinate, 0, saltKey, 0, PUBLIC_COORDINATE_LENGTH);
        System.arraycopy(recipientPublicCoordinate, 0, saltKey, PUBLIC_COORDINATE_LENGTH, PUBLIC_COORDINATE_LENGTH);
        return new SharedSaltKey(saltKey);
    }

    private static byte[] getPublicCoordinate(final PublicKey publicKey) {
        final byte[] encoded = publicKey.getEncoded();
        final int encodedLength = encoded.length;
        final int headerLength = encodedLength - PUBLIC_COORDINATE_LENGTH;
        return getPublicCoordinate(encoded, headerLength);
    }

    private static byte[] getPublicCoordinate(final byte[] encoded, final int startPosition) {
        final byte[] publicCoordinate = new byte[PUBLIC_COORDINATE_LENGTH];
        System.arraycopy(encoded, startPosition, publicCoordinate, 0, PUBLIC_COORDINATE_LENGTH);
        return publicCoordinate;
    }
}
