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

import java.security.GeneralSecurityException;

/**
 * Message Authentication Code Producer Factory creates new producers using required arguments
 */
public final class MessageAuthenticationCodeProducerFactory {
    private MessageAuthenticationCodeProducerFactory() {

    }

    /**
     * Create a new instance of Message Authentication Code Producer using MAC Key
     *
     * @param macKey Message Authentication Code Key required
     * @return Message Authentication Code Producer
     * @throws GeneralSecurityException Thrown on producer initialization failures
     */
    public static MessageAuthenticationCodeProducer newMessageAuthenticationCodeProducer(final MacKey macKey) throws GeneralSecurityException {
        return new StandardMessageAuthenticationCodeProducer(macKey);
    }
}
