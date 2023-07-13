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
package com.exceptionfactory.jagged.framework.crypto;

import javax.crypto.spec.IvParameterSpec;

/**
 * Initialization Vector Parameter Specification for Payload encryption and decryption consisting of 12 bytes
 */
public final class PayloadIvParameterSpec extends IvParameterSpec {
    private static final int LAST_INITIALIZATION_VECTOR_COUNTER_INDEX = 10;

    private static final int LAST_CHUNK_FLAG_INDEX = 11;

    private static final int LAST_CHUNK_FLAG = 1;

    private static final int INITIALIZATION_VECTOR_LENGTH = 12;

    private final byte[] initializationVector;

    /**
     * Payload Initialization Vector Parameter Specification with starting initialization vector of 12 bytes
     */
    public PayloadIvParameterSpec() {
        this(new byte[INITIALIZATION_VECTOR_LENGTH]);
    }

    /**
     * Payload Initialization Vector Parameter Specification constructor with provided initial vector of 12 bytes
     *
     * @param initializationVector Initialization Vector of 12 bytes
     */
    PayloadIvParameterSpec(final byte[] initializationVector) {
        super(getValidatedInitializationVector(initializationVector));
        this.initializationVector = initializationVector;
    }

    /**
     * Get Initialization Vector
     *
     * @return Initialization Vector bytes
     */
    @Override
    public byte[] getIV() {
        return initializationVector.clone();
    }

    /**
     * Increment Payload Initialization Vector starting with next to last byte described in age-encryption Payload specification
     */
    public void incrementInitializationVector() {
        boolean incrementRequired = true;
        int i = LAST_INITIALIZATION_VECTOR_COUNTER_INDEX;
        while (incrementRequired) {
            initializationVector[i]++;
            if (initializationVector[i] != 0) {
                incrementRequired = false;
            } else if (i == 0) {
                throw new IllegalStateException("Maximum counter size exceeded");
            }
            i--;
        }
    }

    /**
     * Set Last Chunk Flag in Payload Initialization Vector as described in age-encryption Payload specification
     */
    public void setLastChunkFlag() {
        initializationVector[LAST_CHUNK_FLAG_INDEX] = LAST_CHUNK_FLAG;
    }

    /**
     * Determine not first chunk status based on current initialization vector bytes
     *
     * @return Not First Chunk status
     */
    public boolean isNotFirstChunk() {
        boolean notFirstChunk = false;

        for (int i = 0; i < LAST_CHUNK_FLAG_INDEX; i++) {
            final byte counter = initializationVector[i];
            if (counter != 0) {
                notFirstChunk = true;
                break;
            }
        }

        return notFirstChunk;
    }

    private static byte[] getValidatedInitializationVector(final byte[] initializationVector) {
        final byte[] validatedInitializationVector;
        if (initializationVector == null) {
            throw new IllegalArgumentException("Initialization Vector required");
        } else if (initializationVector.length == INITIALIZATION_VECTOR_LENGTH) {
            validatedInitializationVector = initializationVector;
        } else {
            final String message = String.format("Initialization Vector length [%d] not required length [%d]", initializationVector.length, INITIALIZATION_VECTOR_LENGTH);
            throw new IllegalArgumentException(message);
        }
        return validatedInitializationVector;
    }
}
