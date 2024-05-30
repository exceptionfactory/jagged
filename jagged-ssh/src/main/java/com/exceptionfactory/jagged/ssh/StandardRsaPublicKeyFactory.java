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

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;

/**
 * Standard implementation of RSA Public Key Factory
 */
class StandardRsaPublicKeyFactory implements RsaPublicKeyFactory {
    /**
     * Get RSA Public Key
     *
     * @param privateKey RSA Private Key
     * @return RSA Public Key
     * @throws GeneralSecurityException Thrown on failure to convert private key to public key
     */
    @Override
    public RSAPublicKey getPublicKey(final RSAPrivateCrtKey privateKey) throws GeneralSecurityException {
        Objects.requireNonNull(privateKey, "RSA Private Key required");

        final KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm());
        final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }
}
