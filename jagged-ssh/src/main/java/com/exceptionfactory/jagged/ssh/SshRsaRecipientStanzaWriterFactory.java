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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;

/**
 * Factory abstraction for returning initialized ssh-rsa Recipient Stanza Writer from an RSA Public Key
 */
public final class SshRsaRecipientStanzaWriterFactory {
    private SshRsaRecipientStanzaWriterFactory() {

    }

    /**
     * Create new ssh-rsa Recipient Stanza Writer using an RSA Public Key
     *
     * @param rsaPublicKey RSA Public Key
     * @return ssh-rsa Recipient Stanza Writer
     */
    public static RecipientStanzaWriter newRecipientStanzaWriter(final RSAPublicKey rsaPublicKey) {
        return new SshRsaRecipientStanzaWriter(rsaPublicKey);
    }

    /**
     * Create new ssh-rsa Recipient Stanza Writer using an RSA Public Key
     *
     * @param encoded Byte array containing an SSH RSA public key
     * @return ssh-rsa Recipient Stanza Writer
     * @throws GeneralSecurityException Thrown in failure to read public key
     */
    public static RecipientStanzaWriter newRecipientStanzaWriter(final byte[] encoded) throws GeneralSecurityException {
        final SshRsaPublicKeyReader publicKeyReader = new SshRsaPublicKeyReader();
        final ByteBuffer inputBuffer = ByteBuffer.wrap(encoded);
        final RSAPublicKey rsaPublicKey = publicKeyReader.read(inputBuffer);
        return newRecipientStanzaWriter(rsaPublicKey);
    }
}
