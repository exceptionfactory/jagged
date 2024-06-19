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
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * SSH RSA implementation reads the RSA Private Key portion of an OpenSSH Version 1 Key
 */
class SshRsaOpenSshKeyPairReader extends OpenSshKeyByteBufferReader {
    private static final String RSA_ALGORITHM = "RSA";

    /**
     * Read RSA Private CRT Key from bytes and derive Public Key to return Key Pair
     *
     * @param buffer Input Buffer to be read
     * @return RSA Public and Private Key Pair
     * @throws GeneralSecurityException Thrown on failures to parse input buffer
     */
    @Override
    public KeyPair read(final ByteBuffer buffer) throws GeneralSecurityException {
        final RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = readRsaPrivateKeySpec(buffer);
        return readKeyPair(rsaPrivateCrtKeySpec);
    }

    private KeyPair readKeyPair(final RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec) throws GeneralSecurityException {
        final RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKeySpec.getModulus(), rsaPrivateCrtKeySpec.getPublicExponent());

        final KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        final PrivateKey privateKey = keyFactory.generatePrivate(rsaPrivateCrtKeySpec);
        final PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    private RSAPrivateCrtKeySpec readRsaPrivateKeySpec(final ByteBuffer buffer) throws InvalidKeyException {
        final BigInteger modulus = readBigInteger(buffer);
        final BigInteger publicExponent = readBigInteger(buffer);
        final BigInteger privateExponent = readBigInteger(buffer);
        final BigInteger crtCoefficient = readBigInteger(buffer);
        final BigInteger primeP = readBigInteger(buffer);
        final BigInteger primeQ = readBigInteger(buffer);

        // Calculate exponents according to RFC 8017 Section 3.2
        final BigInteger primeExponentP = privateExponent.remainder(primeP.subtract(BigInteger.ONE));
        final BigInteger primeExponentQ = privateExponent.remainder(primeQ.subtract(BigInteger.ONE));
        return new RSAPrivateCrtKeySpec(
                modulus,
                publicExponent,
                privateExponent,
                primeP,
                primeQ,
                primeExponentP,
                primeExponentQ,
                crtCoefficient
        );
    }
}
