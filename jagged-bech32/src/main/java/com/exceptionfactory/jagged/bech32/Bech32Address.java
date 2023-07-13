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
package com.exceptionfactory.jagged.bech32;

/**
 * Bech32 Address containing the human-readable part and the data without the separator or checksum
 */
public interface Bech32Address {
    /**
     * Get the human-readable part of the address prior to the separator
     *
     * @return Human-readable part of the address
     */
    CharSequence getHumanReadablePart();

    /**
     * Get the data portion of the address after the separator but without the trailing checksum
     *
     * @return Data portion of the address
     */
    byte[] getData();
}
