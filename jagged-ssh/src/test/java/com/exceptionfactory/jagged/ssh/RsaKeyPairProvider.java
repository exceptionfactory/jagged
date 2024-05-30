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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

final class RsaKeyPairProvider {
    private static final String KEY_ALGORITHM = "RSA";

    private static final int KEY_SIZE = 4096;

    private static RSAPublicKey rsaPublicKey;

    private static RSAPrivateCrtKey rsaPrivateCrtKey;

    private RsaKeyPairProvider() {

    }

    static synchronized RSAPublicKey getRsaPublicKey() throws NoSuchAlgorithmException {
        if (rsaPublicKey == null) {
            setKeyPair();
        }
        return rsaPublicKey;
    }

    static synchronized RSAPrivateCrtKey getRsaPrivateCrtKey() throws NoSuchAlgorithmException {
        if (rsaPrivateCrtKey == null) {
            setKeyPair();
        }
        return rsaPrivateCrtKey;
    }

    private static void setKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        rsaPrivateCrtKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    }
}
