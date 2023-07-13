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
package com.exceptionfactory.jagged.test;

import com.exceptionfactory.jagged.PayloadException;
import com.exceptionfactory.jagged.UnsupportedRecipientStanzaException;
import com.exceptionfactory.jagged.framework.armor.ArmoredDecodingException;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

/**
 * Community Cryptography Test Vector expected results
 */
enum CommunityCryptographyExpectation {
    SUCCESS("success", null),

    NO_MATCH("no match", UnsupportedRecipientStanzaException.class),

    HMAC_FAILURE("HMAC failure", SignatureException.class),

    HEADER_FAILURE("header failure", GeneralSecurityException.class),

    PAYLOAD_FAILURE("payload failure", PayloadException.class),

    ARMOR_FAILURE("armor failure", ArmoredDecodingException.class);

    private final String label;

    private final Class<? extends Exception> exceptionClass;

    CommunityCryptographyExpectation(final String label, final Class<? extends Exception> exceptionClass) {
        this.label = label;
        this.exceptionClass = exceptionClass;
    }

    String getLabel() {
        return label;
    }

    Class<? extends Exception> getExceptionClass() {
        return exceptionClass;
    }
}
