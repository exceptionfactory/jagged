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
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/**
 * SSH RSA implementation of Public Key Marshaller writes the RSA exponent and modulus along with the key algorithm
 */
class SshRsaPublicKeyMarshaller implements PublicKeyMarshaller<RSAPublicKey> {
    private static final byte[] SSH_RSA_ALGORITHM = SshRsaRecipientIndicator.STANZA_TYPE.getIndicator().getBytes(StandardCharsets.UTF_8);

    private static final int BUFFER_SIZE = 1024;

    /**
     * Get Public Key marshalled according to SSH wire format requirements
     *
     * @param publicKey RSA Public Key to be marshalled
     * @return Byte array containing marshalled public key with ssh-rsa algorithm, exponent, and modulus
     */
    @Override
    public byte[] getMarshalledKey(final RSAPublicKey publicKey) {
        Objects.requireNonNull(publicKey, "RSA Public Key required");

        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        writeBytes(buffer, SSH_RSA_ALGORITHM);

        final BigInteger publicExponent = publicKey.getPublicExponent();
        writeBytes(buffer, publicExponent.toByteArray());

        final BigInteger modulus = publicKey.getModulus();
        writeBytes(buffer, modulus.toByteArray());

        final byte[] marshalledKey = new byte[buffer.position()];
        buffer.flip();
        buffer.get(marshalledKey);
        return marshalledKey;
    }

    private void writeBytes(final ByteBuffer buffer, final byte[] bytes) {
        buffer.putInt(bytes.length);
        buffer.put(bytes);
    }
}
