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
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.EncryptedFileKey;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptor;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import static com.exceptionfactory.jagged.ssh.SshEd25519RecipientIndicator.STANZA_TYPE;

/**
 * SSH Ed25519 implementation of Recipient Stanza Reader compatible with age-ssh
 */
final class SshEd25519RecipientStanzaReader implements RecipientStanzaReader {
    private static final int EPHEMERAL_SHARE_ENCODED_LENGTH = 43;

    private static final int ENCRYPTED_FILE_KEY_LENGTH = 32;

    private static final CanonicalBase64.Decoder BASE64_DECODER = CanonicalBase64.getDecoder();

    private static final SshEd25519PublicKeyMarshaller PUBLIC_KEY_MARSHALLER = new SshEd25519PublicKeyMarshaller();

    private static final PublicKeyFingerprintProducer PUBLIC_KEY_FINGERPRINT_PRODUCER = new StandardPublicKeyFingerprintProducer();

    private final Ed25519KeyConverter keyConverter;

    private final SharedSecretKeyProducer sharedSecretKeyProducer;

    private final SharedSecretKeyProducer derivedSharedSecretKeyProducer;

    private final SharedWrapKeyProducer sharedWrapKeyProducer;

    private final FileKeyDecryptor fileKeyDecryptor;

    private final String publicKeyFingerprint;

    /**
     * SSH Ed25519 Recipient Stanza Reader with Ed25519 Key Pair for decryption of File Key
     *
     * @param publicKey Ed25519 Public Key
     * @param privateKey Ed25519 Private Key
     * @param keyPairGeneratorFactory X25519 Key Pair Generator Factory
     * @param keyAgreementFactory X25519 Key Agreement Factory
     * @param fileKeyDecryptor File Key Decryptor
     * @throws GeneralSecurityException Thrown on failures to derive Public Key
     */
    SshEd25519RecipientStanzaReader(
            final Ed25519PublicKey publicKey,
            final Ed25519PrivateKey privateKey,
            final X25519KeyPairGeneratorFactory keyPairGeneratorFactory,
            final X25519KeyAgreementFactory keyAgreementFactory,
            final FileKeyDecryptor fileKeyDecryptor
    ) throws GeneralSecurityException {
        Objects.requireNonNull(publicKey, "Public Key required");
        Objects.requireNonNull(privateKey, "Private Key required");
        Objects.requireNonNull(keyPairGeneratorFactory, "Key Pair Generator Factory required");
        Objects.requireNonNull(keyAgreementFactory, "Key Agreement Factory required");
        this.fileKeyDecryptor = Objects.requireNonNull(fileKeyDecryptor, "File Key Decryptor required");

        final byte[] marshalledKey = PUBLIC_KEY_MARSHALLER.getMarshalledKey(publicKey);
        publicKeyFingerprint = PUBLIC_KEY_FINGERPRINT_PRODUCER.getFingerprint(marshalledKey);

        keyConverter = new StandardEd25519KeyConverter(keyPairGeneratorFactory);
        final PrivateKey privateKeyConverted = keyConverter.getPrivateKey(privateKey);
        sharedSecretKeyProducer = new X25519SharedSecretKeyProducer(privateKeyConverted, keyAgreementFactory);
        sharedWrapKeyProducer = getWrapKeyProducer();

        final SshEd25519SharedWrapKeyProducer sshEd25519SharedWrapKeyProducer = new SshEd25519SharedWrapKeyProducer();
        final SshEd25519DerivedKey sshEd25519DerivedKey = sshEd25519SharedWrapKeyProducer.getDerivedKey(publicKey);
        final PrivateKey derivedPrivateKey = keyConverter.getPrivateKey(sshEd25519DerivedKey);
        derivedSharedSecretKeyProducer = new X25519SharedSecretKeyProducer(derivedPrivateKey, keyAgreementFactory);
    }

    /**
     * Get File Key from matching ssh-ed25519 Recipient Stanza
     *
     * @param recipientStanzas One or more Recipient Stanzas parsed from the age file header
     * @return File Key decrypted from matching ssh-ed25519 Recipient Stanza arguments
     * @throws GeneralSecurityException Thrown on failure to read or decrypt File Key
     */
    @Override
    public FileKey getFileKey(final Iterable<RecipientStanza> recipientStanzas) throws GeneralSecurityException {
        Objects.requireNonNull(recipientStanzas, "Recipient Stanzas required");

        final List<Exception> exceptions = new ArrayList<>();
        for (final RecipientStanza recipientStanza : recipientStanzas) {
            final String recipientStanzaType = recipientStanza.getType();
            if (STANZA_TYPE.getIndicator().equals(recipientStanzaType)) {
                try {
                    return getFileKey(recipientStanza);
                } catch (final Exception e) {
                    exceptions.add(e);
                }
            }
        }

        if (exceptions.isEmpty()) {
            throw new UnsupportedRecipientStanzaException(String.format("%s Recipient Stanzas not found", STANZA_TYPE.getIndicator()));
        } else {
            final String message = String.format("%s Recipient Stanza not matched", STANZA_TYPE.getIndicator());
            final UnsupportedRecipientStanzaException exception = new UnsupportedRecipientStanzaException(message);
            exceptions.forEach(exception::addSuppressed);
            throw exception;
        }
    }

    private FileKey getFileKey(final RecipientStanza recipientStanza) throws GeneralSecurityException {
        final Iterator<String> recipientStanzaArguments = recipientStanza.getArguments().iterator();
        final String recipientKeyFingerprint = getRecipientKeyFingerprint(recipientStanzaArguments);

        if (publicKeyFingerprint.equals(recipientKeyFingerprint)) {
            final SharedSecretKey ephemeralSharedSecretKey = getEphemeralSharedSecretKey(recipientStanzaArguments);
            final PublicKey ephemeralSharedPublicKey = keyConverter.getPublicKey(ephemeralSharedSecretKey);
            final SharedSecretKey sharedSecretKey = sharedSecretKeyProducer.getSharedSecretKey(ephemeralSharedPublicKey);
            final PublicKey sharedPublicKey = keyConverter.getPublicKey(sharedSecretKey);

            final SharedSecretKey derivedSharedSecretKey = derivedSharedSecretKeyProducer.getSharedSecretKey(sharedPublicKey);
            final CipherKey wrapKey = sharedWrapKeyProducer.getWrapKey(derivedSharedSecretKey, ephemeralSharedPublicKey);

            final byte[] encryptedFileKeyEncoded = recipientStanza.getBody();
            final int encryptedFileKeyLength = encryptedFileKeyEncoded.length;
            if (encryptedFileKeyLength == ENCRYPTED_FILE_KEY_LENGTH) {
                final EncryptedFileKey encryptedFileKey = new EncryptedFileKey(encryptedFileKeyEncoded);
                return fileKeyDecryptor.getFileKey(encryptedFileKey, wrapKey);
            } else {
                final String message = String.format("Recipient Stanza Body length [%d] not required length [%d]", encryptedFileKeyLength, ENCRYPTED_FILE_KEY_LENGTH);
                throw new UnsupportedRecipientStanzaException(message);
            }
        } else {
            final String message = String.format("%s Recipient Stanza Key Fingerprint [%s] not matched", STANZA_TYPE.getIndicator(), recipientKeyFingerprint);
            throw new UnsupportedRecipientStanzaException(message);
        }
    }

    private SharedSecretKey getEphemeralSharedSecretKey(final Iterator<String> recipientStanzaArguments) throws UnsupportedRecipientStanzaException {
        if (recipientStanzaArguments.hasNext()) {
            final String ephemeralShareEncoded = recipientStanzaArguments.next();

            if (recipientStanzaArguments.hasNext()) {
                final String message = String.format("%s Recipient Stanza extra argument not expected", STANZA_TYPE.getIndicator());
                throw new UnsupportedRecipientStanzaException(message);
            }

            final int encodedLength = ephemeralShareEncoded.length();
            if (EPHEMERAL_SHARE_ENCODED_LENGTH == encodedLength) {
                final byte[] ephemeralShareEncodedBytes = ephemeralShareEncoded.getBytes(StandardCharsets.US_ASCII);
                final byte[] ephemeralShare = BASE64_DECODER.decode(ephemeralShareEncodedBytes);
                return new SharedSecretKey(ephemeralShare);
            } else {
                final String message = String.format("%s ephemeral share length [%d] not expected", STANZA_TYPE.getIndicator(), encodedLength);
                throw new UnsupportedRecipientStanzaException(message);
            }
        } else {
            final String message = String.format("%s ephemeral share argument not found", STANZA_TYPE.getIndicator());
            throw new UnsupportedRecipientStanzaException(message);
        }
    }

    private String getRecipientKeyFingerprint(final Iterator<String> arguments) throws UnsupportedRecipientStanzaException {
        if (arguments.hasNext()) {
            return arguments.next();
        } else {
            throw new UnsupportedRecipientStanzaException("Key Fingerprint argument not found");
        }
    }

    private SharedWrapKeyProducer getWrapKeyProducer() throws GeneralSecurityException {
        final X25519BasePointPublicKey basePointPublicKey = new X25519BasePointPublicKey();
        final SharedSecretKey basePointPublicKeyEncoded = new SharedSecretKey(basePointPublicKey.getEncoded());
        final PublicKey basePointPublicKeyConverted = keyConverter.getPublicKey(basePointPublicKeyEncoded);
        final SharedSecretKey basePointSharedSecretKey = sharedSecretKeyProducer.getSharedSecretKey(basePointPublicKeyConverted);
        final PublicKey recipientPublicKey = keyConverter.getPublicKey(basePointSharedSecretKey);
        return new X25519SharedWrapKeyProducer(recipientPublicKey);
    }
}
