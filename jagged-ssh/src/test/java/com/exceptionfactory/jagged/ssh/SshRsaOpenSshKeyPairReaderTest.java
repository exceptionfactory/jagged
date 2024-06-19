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

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SshRsaOpenSshKeyPairReaderTest {
    private static final String RSA_ALGORITHM = "RSA";

    private static final int BUFFER_SIZE = 4096;

    private final SshRsaOpenSshKeyPairReader reader = new SshRsaOpenSshKeyPairReader();

    @Test
    void testRead() throws GeneralSecurityException {
        final ByteBuffer inputBuffer = getPrivateKeyBuffer();
        final KeyPair keyPair = reader.read(inputBuffer);

        assertNotNull(keyPair);

        final PrivateKey privateKey = keyPair.getPrivate();
        assertNotNull(privateKey);

        final PublicKey publicKey = keyPair.getPublic();
        assertNotNull(publicKey);

        assertEquals(RSA_ALGORITHM, privateKey.getAlgorithm());
        assertEquals(RSA_ALGORITHM, publicKey.getAlgorithm());
    }

    ByteBuffer getPrivateKeyBuffer() throws NoSuchAlgorithmException {
        final ByteBuffer inputBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        final RSAPrivateCrtKey rsaPrivateCrtKey = RsaKeyPairProvider.getRsaPrivateCrtKey();

        putBigInteger(inputBuffer, rsaPrivateCrtKey.getModulus());
        putBigInteger(inputBuffer, rsaPrivateCrtKey.getPublicExponent());
        putBigInteger(inputBuffer, rsaPrivateCrtKey.getPrivateExponent());
        putBigInteger(inputBuffer, rsaPrivateCrtKey.getCrtCoefficient());
        putBigInteger(inputBuffer, rsaPrivateCrtKey.getPrimeP());
        putBigInteger(inputBuffer, rsaPrivateCrtKey.getPrimeQ());

        inputBuffer.flip();
        return inputBuffer;
    }

    private void putBigInteger(final ByteBuffer buffer, final BigInteger bigInteger) {
        final byte[] bytes = bigInteger.toByteArray();
        buffer.putInt(bytes.length);
        buffer.put(bytes);
    }
}
