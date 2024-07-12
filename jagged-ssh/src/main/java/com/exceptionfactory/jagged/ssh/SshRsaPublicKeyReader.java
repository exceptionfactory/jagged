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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * SSH RSA Public Key Reader implementation based on ssh-rsa format described in RFC 4253 Section 6.6
 */
class SshRsaPublicKeyReader extends SshPublicKeyReader<RSAPublicKey> {
    private static final String KEY_ALGORITHM = "RSA";

    /**
     * SSH RSA Public Key Reader constructor configures the expected ssh-rsa algorithm
     */
    SshRsaPublicKeyReader() {
        super(SshRsaRecipientIndicator.STANZA_TYPE.getIndicator());
    }

    /**
     * Read RSA Public Key from encoded public exponent and modulus
     *
     * @param decodedBuffer Buffer of bytes decoded from Base64 public key
     * @return RSA Public Key
     * @throws GeneralSecurityException Thrown on failures to generate RSA public key from specification
     */
    @Override
    protected RSAPublicKey readPublicKey(final ByteBuffer decodedBuffer) throws GeneralSecurityException {
        final byte[] publicExponentBlock = readBlock(decodedBuffer);
        final BigInteger publicExponent = new BigInteger(publicExponentBlock);

        final byte[] modulusBlock = readBlock(decodedBuffer);
        final BigInteger modulus = new BigInteger(modulusBlock);

        final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        final KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return (RSAPublicKey) publicKey;
    }
}
