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

import com.exceptionfactory.jagged.FileKey;
import com.exceptionfactory.jagged.RecipientStanza;
import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.crypto.CipherKey;
import com.exceptionfactory.jagged.framework.crypto.EncryptedFileKey;
import com.exceptionfactory.jagged.framework.crypto.FileKeyEncryptor;
import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Objects;

/**
 * Standard age-encryption Recipient Stanza Writer implementation using scrypt password-based key derivation as described in RFC 7914
 */
class ScryptRecipientStanzaWriter implements RecipientStanzaWriter {
    private static final int SALT_LENGTH = 16;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final CanonicalBase64.Encoder ENCODER = CanonicalBase64.getEncoder();

    private final DerivedWrapKeyProducer derivedWrapKeyProducer;

    private final int workFactor;

    private final FileKeyEncryptor fileKeyEncryptor;

    /**
     * scrypt Recipient Stanza Writer with wrap key producer containing passphrase and work factor for key derivation
     *
     * @param derivedWrapKeyProducer Derived Wrap Key Producer based on supplied passphrase
     * @param workFactor scrypt work factor
     * @param fileKeyEncryptor File Key Encryptor
     */
    ScryptRecipientStanzaWriter(final DerivedWrapKeyProducer derivedWrapKeyProducer, final int workFactor, final FileKeyEncryptor fileKeyEncryptor) {
        this.derivedWrapKeyProducer = Objects.requireNonNull(derivedWrapKeyProducer, "Wrap Key Producer required");
        this.workFactor = workFactor;
        this.fileKeyEncryptor = Objects.requireNonNull(fileKeyEncryptor, "File Key Encryptor required");
    }

    /**
     * Get Recipient Stanzas containing one scrypt Recipient Stanza with the encrypted File Key
     *
     * @param fileKey File Key to be encrypted
     * @return Singleton List of scrypt Recipient Stanza with encrypted File Key
     * @throws GeneralSecurityException Thrown key derivation or encryption failures
     */
    @Override
    public Iterable<RecipientStanza> getRecipientStanzas(final FileKey fileKey) throws GeneralSecurityException {
        Objects.requireNonNull(fileKey, "File Key required");

        final byte[] salt = getSalt();
        final CipherKey wrapKey = derivedWrapKeyProducer.getWrapKey(salt, workFactor);
        final EncryptedFileKey encryptedFileKey = fileKeyEncryptor.getEncryptedFileKey(fileKey, wrapKey);
        final byte[] encryptedFileKeyEncoded = encryptedFileKey.getEncoded();

        final String saltEncoded = ENCODER.encodeToString(salt);
        final RecipientStanza recipientStanza = new ScryptRecipientStanza(saltEncoded, workFactor, encryptedFileKeyEncoded);
        return Collections.singletonList(recipientStanza);
    }

    private byte[] getSalt() {
        final byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }
}
