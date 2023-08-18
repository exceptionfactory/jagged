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

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.EncryptedFileKey;
import com.exceptionfactory.jagged.framework.crypto.FileKeyEncryptor;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Objects;

/**
 * Standard age-encryption Recipient Stanza Writer implementation using X25519 Key Exchange described in RFC 7748 Section 5
 */
class X25519RecipientStanzaWriter implements RecipientStanzaWriter {
    private static final int EPHEMERAL_PRIVATE_KEY_LENGTH = RecipientKeyType.X25519.getKeyLength();

    private static final BasePointPublicKey BASE_POINT_PUBLIC_KEY = new BasePointPublicKey();

    private static final CanonicalBase64.Encoder ENCODER = CanonicalBase64.getEncoder();

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final PublicKey recipientPublicKey;

    private final RecipientKeyFactory recipientKeyFactory;

    private final SharedWrapKeyProducer sharedWrapKeyProducer;

    private final FileKeyEncryptor fileKeyEncryptor;

    private final KeyAgreementFactory keyAgreementFactory;

    /**
     * X25519 Recipient Stanza Writer constructor with required Recipient Public Key and collaborating components
     *
     * @param recipientPublicKey Recipient Public Key for the intended receiver of encrypted files
     * @param recipientKeyFactory Recipient Key Factory for producing Key objects
     * @param sharedWrapKeyProducer Wrap Key Producer for deriving encryption key from ephemeral share and Recipient Public Key
     * @param fileKeyEncryptor File Key Decryptor to read File Key encrypted using ChaCha20-Poly1305
     * @param keyAgreementFactory Key Agreement Factory for X25519
     */
    X25519RecipientStanzaWriter(
            final PublicKey recipientPublicKey,
            final RecipientKeyFactory recipientKeyFactory,
            final SharedWrapKeyProducer sharedWrapKeyProducer,
            final FileKeyEncryptor fileKeyEncryptor,
            final KeyAgreementFactory keyAgreementFactory
    ) {
        this.recipientPublicKey = Objects.requireNonNull(recipientPublicKey, "Recipient Public Key required");
        this.recipientKeyFactory = Objects.requireNonNull(recipientKeyFactory, "Recipient Key Factory required");
        this.sharedWrapKeyProducer = Objects.requireNonNull(sharedWrapKeyProducer, "Wrap Key Producer required");
        this.fileKeyEncryptor = Objects.requireNonNull(fileKeyEncryptor, "File Key Encryptor required");
        this.keyAgreementFactory = Objects.requireNonNull(keyAgreementFactory, "Key Agreement Factory required");
    }

    /**
     * Get Recipient Stanzas containing one X25519 Recipient Stanza with the encrypted File Key
     *
     * @param fileKey File Key to be encrypted
     * @return Singleton List of X25519 Recipient Stanza with encrypted File Key
     * @throws GeneralSecurityException Thrown key processing or encryption failures
     */
    @Override
    public Iterable<RecipientStanza> getRecipientStanzas(final FileKey fileKey) throws GeneralSecurityException {
        Objects.requireNonNull(fileKey, "File Key required");

        final SharedSecretKeyProducer sharedSecretKeyProducer = getSharedSecretKeyProducer();
        final SharedSecretKey ephemeralSharedSecretKey = getEphemeralSharedSecretKey(sharedSecretKeyProducer);
        final CipherKey wrapKey = getWrapKey(sharedSecretKeyProducer, ephemeralSharedSecretKey);
        final EncryptedFileKey encryptedFileKey = fileKeyEncryptor.getEncryptedFileKey(fileKey, wrapKey);
        final byte[] encryptedFileKeyEncoded = encryptedFileKey.getEncoded();

        final String ephemeralShareEncoded = ENCODER.encodeToString(ephemeralSharedSecretKey.getEncoded());
        final RecipientStanza recipientStanza = new X25519RecipientStanza(ephemeralShareEncoded, encryptedFileKeyEncoded);
        return Collections.singletonList(recipientStanza);
    }

    private SharedSecretKeyProducer getSharedSecretKeyProducer() throws GeneralSecurityException {
        final byte[] ephemeralPrivateKeyEncoded = getEphemeralPrivateKeyEncoded();
        final PrivateKey ephemeralPrivateKey = recipientKeyFactory.getPrivateKey(ephemeralPrivateKeyEncoded);
        return new X25519SharedSecretKeyProducer(ephemeralPrivateKey, keyAgreementFactory);
    }

    private byte[] getEphemeralPrivateKeyEncoded() {
        final byte[] ephemeralPrivateKeyEncoded = new byte[EPHEMERAL_PRIVATE_KEY_LENGTH];
        SECURE_RANDOM.nextBytes(ephemeralPrivateKeyEncoded);
        return ephemeralPrivateKeyEncoded;
    }

    private SharedSecretKey getEphemeralSharedSecretKey(final SharedSecretKeyProducer sharedSecretKeyProducer) throws GeneralSecurityException {
        final PublicKey basePointPublicKey = recipientKeyFactory.getPublicKey(BASE_POINT_PUBLIC_KEY.getEncoded());
        return sharedSecretKeyProducer.getSharedSecretKey(basePointPublicKey);
    }

    private CipherKey getWrapKey(final SharedSecretKeyProducer sharedSecretKeyProducer, final SharedSecretKey ephemeralSharedSecretKey) throws GeneralSecurityException {
        final SharedSecretKey recipientSharedSecretKey = sharedSecretKeyProducer.getSharedSecretKey(recipientPublicKey);
        final PublicKey ephemeralPublicKey = recipientKeyFactory.getPublicKey(ephemeralSharedSecretKey.getEncoded());
        return sharedWrapKeyProducer.getWrapKey(recipientSharedSecretKey, ephemeralPublicKey);
    }
}
