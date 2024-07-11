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

import com.exceptionfactory.jagged.framework.codec.CanonicalBase64;

import java.nio.charset.StandardCharsets;

final class Ed25519KeyPairProvider {

    private static final String PUBLIC_KEY_ENCODED = "HURauP50ZGJDuUkn6tjy/PGQWmTR2FFyDYXP071GP3U";

    private static final String PRIVATE_KEY_ENCODED = "nWNC6CoPYFBs1dSBWSYPFjQ4+APPoH/3DQoB2kCairA";

    private static final CanonicalBase64.Decoder DECODER = CanonicalBase64.getDecoder();

    private static Ed25519PublicKey publicKey;

    private static Ed25519PrivateKey privateKey;

    private Ed25519KeyPairProvider() {

    }

    static synchronized Ed25519PublicKey getPublicKey() {
        if (publicKey == null) {
            setKeyPair();
        }
        return publicKey;
    }

    static synchronized Ed25519PrivateKey getPrivateKey() {
        if (privateKey == null) {
            setKeyPair();
        }
        return privateKey;
    }

    private static void setKeyPair() {
        final byte[] publicKeyEncoded = DECODER.decode(PUBLIC_KEY_ENCODED.getBytes(StandardCharsets.UTF_8));
        publicKey = new Ed25519PublicKey(publicKeyEncoded);

        final byte[] privateKeyEncoded = DECODER.decode(PRIVATE_KEY_ENCODED.getBytes(StandardCharsets.UTF_8));
        privateKey = new Ed25519PrivateKey(privateKeyEncoded);
    }
}
