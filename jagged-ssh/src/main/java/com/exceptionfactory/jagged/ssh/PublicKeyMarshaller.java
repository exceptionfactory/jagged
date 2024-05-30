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

import java.security.PublicKey;

/**
 * SSH Public Key Marshaller abstraction for writing Public Key elements according to SSH wire format requirements
 *
 * @param <T> Public Key Type
 */
interface PublicKeyMarshaller<T extends PublicKey> {
    /**
     * Get Public Key marshalled according to SSH wire format requirements
     *
     * @param publicKey Public Key to be marshalled
     * @return Byte array containing marshalled public key
     */
    byte[] getMarshalledKey(T publicKey);
}
