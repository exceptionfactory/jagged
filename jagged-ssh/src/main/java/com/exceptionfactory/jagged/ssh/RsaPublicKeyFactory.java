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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Abstraction for deriving RSA Public Keys from RSA Private Keys
 */
interface RsaPublicKeyFactory {
    /**
     * Get RSA Public Key
     *
     * @param privateKey RSA Private Key
     * @return RSA Public Key
     * @throws GeneralSecurityException Thrown on failure to convert private key to public key
     */
    RSAPublicKey getPublicKey(RSAPrivateCrtKey privateKey) throws GeneralSecurityException;
}
