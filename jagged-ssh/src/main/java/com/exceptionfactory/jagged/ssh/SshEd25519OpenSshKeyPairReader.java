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
import java.security.KeyPair;

/**
 * SSH Ed25519 implementation reads the Ed25519 Private Key portion of an OpenSSH Version 1 Key
 */
class SshEd25519OpenSshKeyPairReader extends OpenSshKeyByteBufferReader {
    /**
     * Read Ed25519 Key Pair from bytes
     *
     * @param buffer Input Buffer to be read
     * @return Ed25519 Public and Private Key Pair
     * @throws GeneralSecurityException Thrown on failures to parse input buffer
     */
    @Override
    public KeyPair read(final ByteBuffer buffer) throws GeneralSecurityException {
        final byte[] publicKeyBlock = readBlock(buffer);
        final Ed25519PublicKey publicKey = new Ed25519PublicKey(publicKeyBlock);

        final byte[] privatePublicKeyBlock = readBlock(buffer);
        final byte[] privateKeySeed = new byte[EllipticCurveKeyType.ED25519.getKeyLength()];
        System.arraycopy(privatePublicKeyBlock, 0, privateKeySeed, 0, privateKeySeed.length);

        final Ed25519PrivateKey privateKey = new Ed25519PrivateKey(privateKeySeed);
        return new KeyPair(publicKey, privateKey);
    }
}
