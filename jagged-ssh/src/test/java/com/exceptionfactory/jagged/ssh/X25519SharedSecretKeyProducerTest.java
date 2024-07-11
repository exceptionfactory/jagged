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

import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class X25519SharedSecretKeyProducerTest {

    @Test
    void testGetSharedSecretKey() throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EllipticCurveKeyType.X25519.getAlgorithm());

        final KeyPair senderKeyPair = keyPairGenerator.generateKeyPair();
        final KeyPair recipientKeyPair = keyPairGenerator.generateKeyPair();

        final X25519KeyAgreementFactory keyAgreementFactory = new X25519KeyAgreementFactory();

        final X25519SharedSecretKeyProducer senderProducer = new X25519SharedSecretKeyProducer(senderKeyPair.getPrivate(), keyAgreementFactory);
        final SharedSecretKey senderSharedSecretKey = senderProducer.getSharedSecretKey(recipientKeyPair.getPublic());

        final X25519SharedSecretKeyProducer recipientProducer = new X25519SharedSecretKeyProducer(recipientKeyPair.getPrivate(), keyAgreementFactory);
        final SharedSecretKey recipientSharedSecretKey = recipientProducer.getSharedSecretKey(senderKeyPair.getPublic());

        assertArrayEquals(senderSharedSecretKey.getEncoded(), recipientSharedSecretKey.getEncoded());
    }
}
