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
import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.EncryptedFileKey;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptor;
import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import static com.exceptionfactory.jagged.x25519.RecipientIndicator.STANZA_TYPE;

/**
 * Standard age-encryption Recipient Stanza Reader implementation using X25519 Key Exchange described in RFC 7748 Section 5
 */
class X25519RecipientStanzaReader implements RecipientStanzaReader {
    private static final int EPHEMERAL_SHARE_ENCODED_LENGTH = 43;

    private static final int ENCRYPTED_FILE_KEY_LENGTH = 32;

    private static final CanonicalBase64.Decoder BASE64_DECODER = CanonicalBase64.getDecoder();

    private final RecipientKeyFactory recipientKeyFactory;

    private final SharedSecretKeyProducer sharedSecretKeyProducer;

    private final SharedWrapKeyProducer sharedWrapKeyProducer;

    private final FileKeyDecryptor fileKeyDecryptor;

    /**
     * X25519 Recipient Stanza Reader constructor with Shared Secret Producer initialized with Private Key and Wrap Key Producer
     *
     * @param recipientKeyFactory Recipient Key Factory produces Public Key objects from encoded bytes
     * @param sharedSecretKeyProducer Shared Secret Producer initialized with Private Key
     * @param sharedWrapKeyProducer Wrap Key Producer to derive key for decrypting File Key
     * @param fileKeyDecryptor File Key Decryptor to read File Key encrypted using ChaCha20-Poly1305
     */
    X25519RecipientStanzaReader(
            final RecipientKeyFactory recipientKeyFactory,
            final SharedSecretKeyProducer sharedSecretKeyProducer,
            final SharedWrapKeyProducer sharedWrapKeyProducer,
            final FileKeyDecryptor fileKeyDecryptor
    ) {
        this.recipientKeyFactory = Objects.requireNonNull(recipientKeyFactory, "Recipient Key Factory required");
        this.sharedSecretKeyProducer = Objects.requireNonNull(sharedSecretKeyProducer, "Shared Secret Key Provider required");
        this.sharedWrapKeyProducer = Objects.requireNonNull(sharedWrapKeyProducer, "Wrap Key Producer required");
        this.fileKeyDecryptor = Objects.requireNonNull(fileKeyDecryptor, "File Key Decryptor required");
    }

    /**
     * Get File Key from matching X25519 Recipient Stanza
     *
     * @param recipientStanzas One or more Recipient Stanzas parsed from the age file header
     * @return File Key decrypted from matching X25519 Recipient Stanza arguments
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
        final byte[] ephemeralShare = getEphemeralShare(recipientStanzaArguments);
        final PublicKey ephemeralPublicKey = recipientKeyFactory.getPublicKey(ephemeralShare);
        final SharedSecretKey sharedSecretKey = sharedSecretKeyProducer.getSharedSecretKey(ephemeralPublicKey);
        final CipherKey wrapKey = sharedWrapKeyProducer.getWrapKey(sharedSecretKey, ephemeralPublicKey);

        final byte[] encryptedFileKeyEncoded = recipientStanza.getBody();
        final int encryptedFileKeyLength = encryptedFileKeyEncoded.length;
        if (encryptedFileKeyLength == ENCRYPTED_FILE_KEY_LENGTH) {
            final EncryptedFileKey encryptedFileKey = new EncryptedFileKey(encryptedFileKeyEncoded);
            return fileKeyDecryptor.getFileKey(encryptedFileKey, wrapKey);
        } else {
            final String message = String.format("Recipient Stanza Body length [%d] not required length [%d]", encryptedFileKeyLength, ENCRYPTED_FILE_KEY_LENGTH);
            throw new UnsupportedRecipientStanzaException(message);
        }
    }

    private byte[] getEphemeralShare(final Iterator<String> recipientStanzaArguments) throws UnsupportedRecipientStanzaException {
        if (recipientStanzaArguments.hasNext()) {
            final String ephemeralShareEncoded = recipientStanzaArguments.next();

            if (recipientStanzaArguments.hasNext()) {
                final String message = String.format("%s Recipient Stanza extra argument not expected", STANZA_TYPE.getIndicator());
                throw new UnsupportedRecipientStanzaException(message);
            }

            final int encodedLength = ephemeralShareEncoded.length();
            if (EPHEMERAL_SHARE_ENCODED_LENGTH == encodedLength) {
                final byte[] ephemeralShareEncodedBytes = ephemeralShareEncoded.getBytes(StandardCharsets.US_ASCII);
                return BASE64_DECODER.decode(ephemeralShareEncodedBytes);
            } else {
                final String message = String.format("%s ephemeral share length [%d] not expected", STANZA_TYPE.getIndicator(), encodedLength);
                throw new UnsupportedRecipientStanzaException(message);
            }
        } else {
            final String message = String.format("%s ephemeral share argument not found", STANZA_TYPE.getIndicator());
            throw new UnsupportedRecipientStanzaException(message);
        }
    }
}
