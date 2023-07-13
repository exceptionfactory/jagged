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

import javax.crypto.Mac;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * Standard implementation of Message Authentication Code Producer using javax.crypto.Mac with HMAC-SHA-256
 */
class StandardMessageAuthenticationCodeProducer implements MessageAuthenticationCodeProducer {
    private final Mac mac;

    /**
     * Standard Message Authentication Code Producer constructor
     *
     * @param macKey Message Authentication Code Key required
     * @throws GeneralSecurityException Thrown on Message Authentication Code initialization failures
     */
    StandardMessageAuthenticationCodeProducer(final MacKey macKey) throws GeneralSecurityException {
        mac = Mac.getInstance(macKey.getAlgorithm());
        mac.init(macKey);
    }

    /**
     * Get Message Authentication Code using configured Key and provided input bytes
     *
     * @param inputBuffer Input Buffer required
     * @return Message Authentication Code bytes derived from HMAC-SHA-256
     */
    @Override
    public byte[] getMessageAuthenticationCode(final ByteBuffer inputBuffer) {
        Objects.requireNonNull(inputBuffer, "Input Buffer required");
        mac.update(inputBuffer);
        return mac.doFinal();
    }
}
