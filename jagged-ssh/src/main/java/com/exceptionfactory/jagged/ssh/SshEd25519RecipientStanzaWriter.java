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

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.EncryptedFileKey;
import com.exceptionfactory.jagged.framework.crypto.FileKeyEncryptor;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Objects;

/**
 * SSH Ed25519 implementation of Recipient Stanza Writer compatible with age-ssh
 */
final class SshEd25519RecipientStanzaWriter implements RecipientStanzaWriter {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final CanonicalBase64.Encoder ENCODER = CanonicalBase64.getEncoder();

    private final SshEd25519PublicKeyMarshaller publicKeyMarshaller = new SshEd25519PublicKeyMarshaller();

    private final PublicKeyFingerprintProducer publicKeyFingerprintProducer = new StandardPublicKeyFingerprintProducer();

    private final Ed25519PublicKey publicKey;

    private final PublicKey publicKeyConverted;

    private final Ed25519KeyConverter keyConverter;

    private final X25519KeyAgreementFactory keyAgreementFactory;

    private final FileKeyEncryptor fileKeyEncryptor;

    private final SharedSecretKeyProducer derivedSharedSecretKeyProducer;

    /**
     * SSH Ed25519 Recipient Stanza Writer with Ed25519 Public Key
     *
     * @param publicKey Ed25519 Public Key for recipient of encrypted File Key
     * @param keyPairGeneratorFactory X25519 Key Pair Generator Factory for key processing
     * @param keyAgreementFactory X25519 Key Agreement Factory for key derivation
     * @param fileKeyEncryptor File Key Encryptor
     * @throws GeneralSecurityException Thrown on failures to convert between key formats
     */
    SshEd25519RecipientStanzaWriter(
            final Ed25519PublicKey publicKey,
            final X25519KeyPairGeneratorFactory keyPairGeneratorFactory,
            final X25519KeyAgreementFactory keyAgreementFactory,
            final FileKeyEncryptor fileKeyEncryptor
    ) throws GeneralSecurityException {
        this.publicKey = Objects.requireNonNull(publicKey, "Public Key required");
        this.keyAgreementFactory = Objects.requireNonNull(keyAgreementFactory, "Key Agreement Factory required");
        this.fileKeyEncryptor = Objects.requireNonNull(fileKeyEncryptor, "File Key Encryptor required");
        this.keyConverter = new StandardEd25519KeyConverter(keyPairGeneratorFactory);
        this.publicKeyConverted = keyConverter.getPublicKey(publicKey);

        final SshEd25519SharedWrapKeyProducer sshEd25519SharedWrapKeyProducer = new SshEd25519SharedWrapKeyProducer();
        final SshEd25519DerivedKey sshEd25519DerivedKey = sshEd25519SharedWrapKeyProducer.getDerivedKey(publicKey);
        final PrivateKey derivedPrivateKey = keyConverter.getPrivateKey(sshEd25519DerivedKey);
        derivedSharedSecretKeyProducer = new X25519SharedSecretKeyProducer(derivedPrivateKey, keyAgreementFactory);
    }

    /**
     * Get Recipient Stanzas containing one ssh-ed25519 Recipient Stanza with the encrypted File Key
     *
     * @param fileKey File Key to be encrypted
     * @return Singleton List of ssh-ed25519 Recipient Stanza with encrypted File Key
     * @throws GeneralSecurityException Thrown key derivation or encryption failures
     */
    @Override
    public Iterable<RecipientStanza> getRecipientStanzas(final FileKey fileKey) throws GeneralSecurityException {
        Objects.requireNonNull(fileKey, "File Key required");

        final SharedSecretKeyProducer ephemeralSharedSecretKeyProducer = getEphemeralSharedSecretKeyProducer();
        final PublicKey basePointPublicKey = getBasePointPublicKey();
        final SharedSecretKey ephemeralSharedSecretKey = ephemeralSharedSecretKeyProducer.getSharedSecretKey(basePointPublicKey);

        final CipherKey wrapKey = getWrapKey(ephemeralSharedSecretKeyProducer, ephemeralSharedSecretKey);
        final EncryptedFileKey encryptedFileKey = fileKeyEncryptor.getEncryptedFileKey(fileKey, wrapKey);
        final byte[] encryptedFileKeyEncoded = encryptedFileKey.getEncoded();

        final byte[] marshalledKey = publicKeyMarshaller.getMarshalledKey(publicKey);
        final String keyFingerprint = publicKeyFingerprintProducer.getFingerprint(marshalledKey);
        final String ephemeralShare = ENCODER.encodeToString(ephemeralSharedSecretKey.getEncoded());
        final RecipientStanza recipientStanza = new SshEd25519RecipientStanza(keyFingerprint, ephemeralShare, encryptedFileKeyEncoded);
        return Collections.singletonList(recipientStanza);
    }

    private CipherKey getWrapKey(final SharedSecretKeyProducer ephemeralSharedSecretKeyProducer, final SharedSecretKey ephemeralSharedSecretKey) throws GeneralSecurityException {
        final PublicKey ephemeralSharedPublicKey = keyConverter.getPublicKey(ephemeralSharedSecretKey);
        final SharedSecretKey sharedSecretKey = ephemeralSharedSecretKeyProducer.getSharedSecretKey(publicKeyConverted);
        final PublicKey sharedPublicKey = keyConverter.getPublicKey(sharedSecretKey);

        final SharedSecretKey derivedSharedSecretKey = derivedSharedSecretKeyProducer.getSharedSecretKey(sharedPublicKey);
        final SharedWrapKeyProducer sharedWrapKeyProducer = new X25519SharedWrapKeyProducer(publicKeyConverted);
        return sharedWrapKeyProducer.getWrapKey(derivedSharedSecretKey, ephemeralSharedPublicKey);
    }

    private PublicKey getBasePointPublicKey() throws GeneralSecurityException {
        final X25519BasePointPublicKey basePointPublicKey = new X25519BasePointPublicKey();
        final SharedSecretKey basePointPublicKeyEncoded = new SharedSecretKey(basePointPublicKey.getEncoded());
        return keyConverter.getPublicKey(basePointPublicKeyEncoded);
    }

    private SharedSecretKeyProducer getEphemeralSharedSecretKeyProducer() throws GeneralSecurityException {
        final byte[] ephemeralKeyEncoded = getEphemeralKeyEncoded();
        final SshEd25519DerivedKey ephemeralDerivedKey = new SshEd25519DerivedKey(ephemeralKeyEncoded);
        final PrivateKey ephemeralPrivateKey = keyConverter.getPrivateKey(ephemeralDerivedKey);
        return new X25519SharedSecretKeyProducer(ephemeralPrivateKey, keyAgreementFactory);
    }

    private byte[] getEphemeralKeyEncoded() {
        final byte[] ephemeralPrivateKeyEncoded = new byte[EllipticCurveKeyType.X25519.getKeyLength()];
        SECURE_RANDOM.nextBytes(ephemeralPrivateKeyEncoded);
        return ephemeralPrivateKeyEncoded;
    }
}
