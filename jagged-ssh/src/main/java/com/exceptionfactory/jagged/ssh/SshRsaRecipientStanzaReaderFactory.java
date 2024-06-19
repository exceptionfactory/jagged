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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

/**
 * Factory abstraction for returning initialized ssh-rsa Recipient Stanza Readers from an RSA Private Key
 */
public final class SshRsaRecipientStanzaReaderFactory {
    private SshRsaRecipientStanzaReaderFactory() {

    }

    /**
     * Create new ssh-rsa Recipient Stanza Reader using an RSA Private CRT Key
     *
     * @param rsaPrivateCrtKey RSA Private CRT Key
     * @return ssh-rsa Recipient Stanza Reader
     * @throws GeneralSecurityException Thrown on failures to process public key from private key
     */
    public static RecipientStanzaReader newRecipientStanzaReader(final RSAPrivateCrtKey rsaPrivateCrtKey) throws GeneralSecurityException {
        return new SshRsaRecipientStanzaReader(rsaPrivateCrtKey);
    }

    /**
     * Create new ssh-rsa Recipient Stanza Reader using an unencrypted OpenSSH Version 1 RSA Private Key
     *
     * @param encoded Byte array containing an unencrypted OpenSSH Version 1 RSA Private Key
     * @return ssh-rsa Recipient Stanza Reader
     * @throws GeneralSecurityException Thrown on failures to read private or process public key
     */
    public static RecipientStanzaReader newRecipientStanzaReader(final byte[] encoded) throws GeneralSecurityException {
        final OpenSshKeyPairReader openSshKeyPairReader = new OpenSshKeyPairReader();
        final ByteBuffer encodedBuffer = ByteBuffer.wrap(encoded);
        final KeyPair keyPair = openSshKeyPairReader.read(encodedBuffer);
        final PrivateKey privateKey = keyPair.getPrivate();
        final RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
        return newRecipientStanzaReader(rsaPrivateCrtKey);
    }
}
