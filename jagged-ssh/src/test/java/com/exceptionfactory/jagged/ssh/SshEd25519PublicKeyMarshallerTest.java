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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SshEd25519PublicKeyMarshallerTest {
    private static final byte[] SSH_ED25519_ALGORITHM_SERIALIZED = {0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57};

    private SshEd25519PublicKeyMarshaller marshaller;

    @BeforeEach
    void setMarshaller() {
        marshaller = new SshEd25519PublicKeyMarshaller();
    }

    @Test
    void testGetMarshalledKey() {
        final Ed25519PublicKey publicKey = Ed25519KeyPairProvider.getPublicKey();
        final byte[] marshalledKey = marshaller.getMarshalledKey(publicKey);

        assertNotNull(marshalledKey);
        assertEquals(SshEd25519KeyType.MARSHALLED.getKeyLength(), marshalledKey.length);

        final byte[] algorithm = Arrays.copyOfRange(marshalledKey, 0, SSH_ED25519_ALGORITHM_SERIALIZED.length);
        assertArrayEquals(SSH_ED25519_ALGORITHM_SERIALIZED, algorithm);
    }
}
