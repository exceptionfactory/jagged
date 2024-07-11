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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Objects;

/**
 * SSH Ed25519 implementation of Public Key Marshaller writes the Ed25519 public key along with the key algorithm
 */
class SshEd25519PublicKeyMarshaller implements PublicKeyMarshaller<PublicKey> {
    private static final byte[] SSH_ED25519_ALGORITHM = SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator().getBytes(StandardCharsets.UTF_8);

    private static final int BUFFER_SIZE = 128;

    /**
     * Get Public Key marshalled according to SSH wire format requirements
     *
     * @param publicKey Ed25519 Public Key to be marshalled
     * @return Byte array containing marshalled public key with ssh-ed25519 algorithm and public key
     */
    @Override
    public byte[] getMarshalledKey(final PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "Public Key required");

        final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
        writeBytes(buffer, SSH_ED25519_ALGORITHM);
        writeBytes(buffer, publicKey.getEncoded());

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
