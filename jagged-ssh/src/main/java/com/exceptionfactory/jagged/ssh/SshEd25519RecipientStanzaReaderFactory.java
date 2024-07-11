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

import com.exceptionfactory.jagged.RecipientStanzaReader;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptor;
import com.exceptionfactory.jagged.framework.crypto.FileKeyDecryptorFactory;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * Factory abstraction for returning initialized ssh-ed25519 Recipient Stanza Readers from an Ed25519 Private Key
 */
public final class SshEd25519RecipientStanzaReaderFactory {
    private SshEd25519RecipientStanzaReaderFactory() {

    }

    /**
     * Create new ssh-ed25519 Recipient Stanza Reader using an unencrypted OpenSSH Version 1 Ed25519 Private Key
     *
     * @param encoded Byte array containing an unencrypted OpenSSH Version 1 Ed25519 Private Key
     * @return ssh-ed25519 Recipient Stanza Reader
     * @throws GeneralSecurityException Thrown on failures to read private or process public key
     */
    public static RecipientStanzaReader newRecipientStanzaReader(final byte[] encoded) throws GeneralSecurityException {
        final X25519KeyPairGeneratorFactory keyPairGeneratorFactory = new X25519KeyPairGeneratorFactory();
        final X25519KeyAgreementFactory keyAgreementFactory = new X25519KeyAgreementFactory();
        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory();

        return newRecipientStanzaReader(encoded, keyPairGeneratorFactory, keyAgreementFactory, fileKeyDecryptorFactory);
    }

    /**
     * Create new ssh-ed25519 Recipient Stanza Reader using an unencrypted OpenSSH Version 1 Ed25519 Private Key
     *
     * @param encoded Byte array containing an unencrypted OpenSSH Version 1 Ed25519 Private Key
     * @param provider Security Provider for algorithm implementation resolution
     * @return ssh-ed25519 Recipient Stanza Reader
     * @throws GeneralSecurityException Thrown on failures to read private or process public key
     */
    public static RecipientStanzaReader newRecipientStanzaReader(final byte[] encoded, final Provider provider) throws GeneralSecurityException {
        final X25519KeyPairGeneratorFactory keyPairGeneratorFactory = new X25519KeyPairGeneratorFactory(provider);
        final X25519KeyAgreementFactory keyAgreementFactory = new X25519KeyAgreementFactory(provider);
        final FileKeyDecryptorFactory fileKeyDecryptorFactory = new FileKeyDecryptorFactory(provider);

        return newRecipientStanzaReader(encoded, keyPairGeneratorFactory, keyAgreementFactory, fileKeyDecryptorFactory);
    }

    private static RecipientStanzaReader newRecipientStanzaReader(
            final byte[] encoded,
            final X25519KeyPairGeneratorFactory keyPairGeneratorFactory,
            final X25519KeyAgreementFactory keyAgreementFactory,
            final FileKeyDecryptorFactory fileKeyDecryptorFactory
    ) throws GeneralSecurityException {
        final OpenSshKeyPairReader openSshKeyPairReader = new OpenSshKeyPairReader();
        final ByteBuffer encodedBuffer = ByteBuffer.wrap(encoded);
        final KeyPair keyPair = openSshKeyPairReader.read(encodedBuffer);

        final PublicKey publicKey = keyPair.getPublic();
        final Ed25519PublicKey ed25519PublicKey = (Ed25519PublicKey) publicKey;
        final PrivateKey privateKey = keyPair.getPrivate();
        final Ed25519PrivateKey ed25519PrivateKey = (Ed25519PrivateKey) privateKey;

        final FileKeyDecryptor fileKeyDecryptor = fileKeyDecryptorFactory.newFileKeyDecryptor();
        return new SshEd25519RecipientStanzaReader(ed25519PublicKey, ed25519PrivateKey, keyPairGeneratorFactory, keyAgreementFactory, fileKeyDecryptor);
    }
}
