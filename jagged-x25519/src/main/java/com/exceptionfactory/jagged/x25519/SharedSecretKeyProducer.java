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
package com.exceptionfactory.jagged.x25519;

import com.exceptionfactory.jagged.framework.crypto.SharedSecretKey;

import java.security.InvalidKeyException;
import java.security.PublicKey;

/**
 * Abstraction around javax.crypto.KeyAgreement for Shared Secret Key production
 */
interface SharedSecretKeyProducer {
    /**
     * Get Shared Secret Key using provided Public Key
     *
     * @param publicKey Public Key
     * @return Shared Secret Key
     * @throws InvalidKeyException Thrown on failures to produced Shared Secret Key
     */
    SharedSecretKey getSharedSecretKey(PublicKey publicKey) throws InvalidKeyException;
}