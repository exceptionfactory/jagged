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

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Objects;

/**
 * SSH RSA implementation of Recipient Stanza Writer compatible with age-ssh
 */
class SshRsaRecipientStanzaWriter implements RecipientStanzaWriter {
    private final SshRsaPublicKeyMarshaller publicKeyMarshaller = new SshRsaPublicKeyMarshaller();

    private final PublicKeyFingerprintProducer publicKeyFingerprintProducer = new StandardPublicKeyFingerprintProducer();

    private final RsaOaepCipherFactory cipherFactory = new RsaOaepCipherFactory();

    private final RSAPublicKey rsaPublicKey;

    /**
     * SSH RSA Recipient Stanza Writer with RSA Public Key
     *
     * @param rsaPublicKey RSA Public Key for recipient of encrypted File Key
     */
    SshRsaRecipientStanzaWriter(final RSAPublicKey rsaPublicKey) {
        this.rsaPublicKey = Objects.requireNonNull(rsaPublicKey, "RSA Public Key required");
    }

    /**
     * Get Recipient Stanzas containing one ssh-rsa Recipient Stanza with the encrypted File Key
     *
     * @param fileKey File Key to be encrypted
     * @return Singleton List of ssh-rsa Recipient Stanza with encrypted File Key
     * @throws GeneralSecurityException Thrown key derivation or encryption failures
     */
    @Override
    public Iterable<RecipientStanza> getRecipientStanzas(final FileKey fileKey) throws GeneralSecurityException {
        Objects.requireNonNull(fileKey, "File Key required");

        final byte[] marshalledKey = publicKeyMarshaller.getMarshalledKey(rsaPublicKey);
        final String keyFingerprint = publicKeyFingerprintProducer.getFingerprint(marshalledKey);
        final Cipher cipher = cipherFactory.getInitializedCipher(RsaOaepCipherFactory.CipherMode.ENCRYPT, rsaPublicKey);
        final byte[] encryptedFileKey = cipher.doFinal(fileKey.getEncoded());

        final RecipientStanza recipientStanza = new SshRsaRecipientStanza(keyFingerprint, encryptedFileKey);
        return Collections.singletonList(recipientStanza);
    }
}
