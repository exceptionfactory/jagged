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

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import static com.exceptionfactory.jagged.ssh.SshRsaRecipientIndicator.STANZA_TYPE;

/**
 * SSH RSA implementation of Recipient Stanza Reader compatible with age-ssh
 */
final class SshRsaRecipientStanzaReader implements RecipientStanzaReader {
    private final RsaOaepCipherFactory cipherFactory = new RsaOaepCipherFactory();

    private final RSAPrivateCrtKey privateKey;

    private final String publicKeyFingerprint;

    /**
     * SSH RSA Recipient Stanza Reader with RSA Private Key for decryption of File Key
     *
     * @param privateKey RSA Private Key
     * @throws GeneralSecurityException Thrown on failures to derive Public Key
     */
    SshRsaRecipientStanzaReader(final RSAPrivateCrtKey privateKey) throws GeneralSecurityException {
        this.privateKey = Objects.requireNonNull(privateKey, "RSA Private Key required");

        final RsaPublicKeyFactory rsaPublicKeyFactory = new StandardRsaPublicKeyFactory();
        final RSAPublicKey publicKey = rsaPublicKeyFactory.getPublicKey(privateKey);
        final SshRsaPublicKeyMarshaller publicKeyMarshaller = new SshRsaPublicKeyMarshaller();
        final byte[] marshalledKey = publicKeyMarshaller.getMarshalledKey(publicKey);
        final PublicKeyFingerprintProducer publicKeyFingerprintProducer = new StandardPublicKeyFingerprintProducer();
        this.publicKeyFingerprint = publicKeyFingerprintProducer.getFingerprint(marshalledKey);
    }

    /**
     * Get File Key from matching ssh-rsa Recipient Stanza
     *
     * @param recipientStanzas One or more Recipient Stanzas parsed from the age file header
     * @return File Key decrypted from matching ssh-rsa Recipient Stanza arguments
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
        final Iterator<String> arguments = recipientStanza.getArguments().iterator();
        final String recipientKeyFingerprint = getRecipientKeyFingerprint(arguments);

        if (arguments.hasNext()) {
            final String message = String.format("%s Recipient Stanza extra argument not expected", STANZA_TYPE.getIndicator());
            throw new UnsupportedRecipientStanzaException(message);
        }

        if (publicKeyFingerprint.equals(recipientKeyFingerprint)) {
            final byte[] encryptedFileKeyEncoded = recipientStanza.getBody();
            final Cipher cipher = cipherFactory.getInitializedCipher(RsaOaepCipherFactory.CipherMode.DECRYPT, privateKey);
            final byte[] fileKeyEncoded = cipher.doFinal(encryptedFileKeyEncoded);
            return new FileKey(fileKeyEncoded);
        } else {
            final String message = String.format("%s Recipient Stanza Key Fingerprint [%s] not match", STANZA_TYPE.getIndicator(), recipientKeyFingerprint);
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
}
