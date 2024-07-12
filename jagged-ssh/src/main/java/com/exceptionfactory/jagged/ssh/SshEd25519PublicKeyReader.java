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
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * SSH Ed25519 Public Key Reader implementation based on ssh-ed25519 format described in RFC 8709 Section 4
 */
class SshEd25519PublicKeyReader extends SshPublicKeyReader<Ed25519PublicKey> {
    /**
     * SSH Ed25519 Public Key Reader constructor configures the expected ssh-ed25519 algorithm
     */
    SshEd25519PublicKeyReader() {
        super(SshEd25519RecipientIndicator.STANZA_TYPE.getIndicator());
    }

    /**
     * Read Ed25519 Public Key from block of 32 bytes
     *
     * @param decodedBuffer Buffer of bytes decoded from Base64 public key
     * @return Ed25519 Public Key
     * @throws GeneralSecurityException Thrown when block length not equal to expected key length
     */
    @Override
    protected Ed25519PublicKey readPublicKey(final ByteBuffer decodedBuffer) throws GeneralSecurityException {
        final byte[] block = readBlock(decodedBuffer);
        if (EllipticCurveKeyType.ED25519.getKeyLength() == block.length) {
            return new Ed25519PublicKey(block);
        } else {
            final String message = String.format("Public key length [%d] not expected [%d]", block.length, EllipticCurveKeyType.ED25519.getKeyLength());
            throw new InvalidKeyException(message);
        }
    }
}
