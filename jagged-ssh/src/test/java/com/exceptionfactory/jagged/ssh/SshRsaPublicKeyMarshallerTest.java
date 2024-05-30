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
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SshRsaPublicKeyMarshallerTest {
    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    private static final int EXPECTED_LENGTH = 23;

    private static final byte[] SSH_RSA_ALGORITHM_SERIALIZED = {0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97};

    @Mock
    private RSAPublicKey publicKey;

    private SshRsaPublicKeyMarshaller marshaller;

    @BeforeEach
    void setMarshaller() {
        marshaller = new SshRsaPublicKeyMarshaller();
    }

    @Test
    void testGetMarshalledKey() {
        when(publicKey.getPublicExponent()).thenReturn(PUBLIC_EXPONENT);
        when(publicKey.getModulus()).thenReturn(BigInteger.TEN);

        final byte[] marshalledKey = marshaller.getMarshalledKey(publicKey);

        assertNotNull(marshalledKey);
        assertEquals(EXPECTED_LENGTH, marshalledKey.length);

        final byte[] algorithm = Arrays.copyOfRange(marshalledKey, 0, SSH_RSA_ALGORITHM_SERIALIZED.length);
        assertArrayEquals(SSH_RSA_ALGORITHM_SERIALIZED, algorithm);
    }
}
