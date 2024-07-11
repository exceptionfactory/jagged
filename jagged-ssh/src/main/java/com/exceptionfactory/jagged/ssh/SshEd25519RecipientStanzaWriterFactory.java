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

import com.exceptionfactory.jagged.RecipientStanzaWriter;
import com.exceptionfactory.jagged.framework.crypto.FileKeyEncryptor;
import com.exceptionfactory.jagged.framework.crypto.FileKeyEncryptorFactory;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Provider;

/**
 * Factory abstraction for returning initialized ssh-ed25519 Recipient Stanza Writers from an Ed25519 Public Key
 */
public final class SshEd25519RecipientStanzaWriterFactory {
    private SshEd25519RecipientStanzaWriterFactory() {

    }

    /**
     * Create new ssh-ed25519 Recipient Stanza Writer using an SSH Ed25519 public key encoded according to RFC 8709 Section 4
     *
     * @param encoded Byte array containing an SSH Ed25519 public key
     * @return ssh-ed25519 Recipient Stanza Writer
     * @throws GeneralSecurityException Thrown on failures to read or process public key
     */
    public static RecipientStanzaWriter newRecipientStanzaWriter(final byte[] encoded) throws GeneralSecurityException {
        final X25519KeyPairGeneratorFactory keyPairGeneratorFactory = new X25519KeyPairGeneratorFactory();
        final X25519KeyAgreementFactory keyAgreementFactory = new X25519KeyAgreementFactory();
        final FileKeyEncryptorFactory fileKeyEncryptorFactory = new FileKeyEncryptorFactory();

        return newRecipientStanzaWriter(encoded, keyPairGeneratorFactory, keyAgreementFactory, fileKeyEncryptorFactory);
    }

    /**
     * Create new ssh-ed25519 Recipient Stanza Writer using an SSH Ed25519 public key encoded according to RFC 8709 Section 4
     *
     * @param encoded Byte array containing an SSH Ed25519 public key
     * @param provider Security Provider for algorithm implementation resolution
     * @return ssh-ed25519 Recipient Stanza Writer
     * @throws GeneralSecurityException Thrown on failures to read or process public key
     */
    public static RecipientStanzaWriter newRecipientStanzaWriter(final byte[] encoded, final Provider provider) throws GeneralSecurityException {
        final X25519KeyPairGeneratorFactory keyPairGeneratorFactory = new X25519KeyPairGeneratorFactory(provider);
        final X25519KeyAgreementFactory keyAgreementFactory = new X25519KeyAgreementFactory(provider);
        final FileKeyEncryptorFactory fileKeyEncryptorFactory = new FileKeyEncryptorFactory(provider);

        return newRecipientStanzaWriter(encoded, keyPairGeneratorFactory, keyAgreementFactory, fileKeyEncryptorFactory);
    }

    private static RecipientStanzaWriter newRecipientStanzaWriter(
            final byte[] encoded,
            final X25519KeyPairGeneratorFactory keyPairGeneratorFactory,
            final X25519KeyAgreementFactory keyAgreementFactory,
            final FileKeyEncryptorFactory fileKeyEncryptorFactory
    ) throws GeneralSecurityException {
        final SshEd25519PublicKeyReader publicKeyReader = new SshEd25519PublicKeyReader();
        final ByteBuffer inputBuffer = ByteBuffer.wrap(encoded);
        final Ed25519PublicKey publicKey = publicKeyReader.read(inputBuffer);
        final FileKeyEncryptor fileKeyEncryptor = fileKeyEncryptorFactory.newFileKeyEncryptor();
        return new SshEd25519RecipientStanzaWriter(publicKey, keyPairGeneratorFactory, keyAgreementFactory, fileKeyEncryptor);
    }
}
