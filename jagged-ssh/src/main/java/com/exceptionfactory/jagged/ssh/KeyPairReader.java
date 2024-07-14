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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

/**
 * Reader abstraction for loading Public and Private Key Pairs
 */
interface KeyPairReader {
    /**
     * Read Public and Private Key Pair
     *
     * @param inputBuffer Input Buffer to be read
     * @return Public and Private Key Pair
     * @throws GeneralSecurityException Thrown on failures to parse input buffer
     */
    KeyPair read(ByteBuffer inputBuffer) throws GeneralSecurityException;
}
