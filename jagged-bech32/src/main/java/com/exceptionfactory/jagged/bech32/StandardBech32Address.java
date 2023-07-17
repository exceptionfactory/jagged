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

import java.util.Arrays;
import java.util.Objects;

/**
 * Standard implementation of Bech32 Address
 */
class StandardBech32Address implements Bech32Address {
    private final CharSequence humanReadablePart;

    private final byte[] data;

    /**
     * Standard constructor with required properties
     *
     * @param humanReadablePart Human-Readable Part characters
     * @param data Data bytes
     */
    StandardBech32Address(final CharSequence humanReadablePart, final byte[] data) {
        this.humanReadablePart = Objects.requireNonNull(humanReadablePart, "Human-Readable Part required");
        this.data = Objects.requireNonNull(data, "Data required");
    }

    /**
     * Get Human-Readable Part characters
     *
     * @return Human-Readable Part
     */
    @Override
    public CharSequence getHumanReadablePart() {
        return humanReadablePart;
    }

    /**
     * Get Data decoded bytes without checksum
     *
     * @return Data bytes
     */
    @Override
    public byte[] getData() {
        return Arrays.copyOf(data, data.length);
    }
}
