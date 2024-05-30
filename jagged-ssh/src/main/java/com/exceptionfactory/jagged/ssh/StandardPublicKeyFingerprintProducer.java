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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Standard implementation of Public Key Fingerprint Producer using SHA-256 with Base64 encoding for first four bytes
 */
class StandardPublicKeyFingerprintProducer implements PublicKeyFingerprintProducer {
    private static final String DIGEST_ALGORITHM = "SHA-256";

    private static final int FINGERPRINT_DIGEST_LENGTH = 4;

    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();

    /**
     * Get fingerprint from marshalled Public Key bytes following age-ssh implementation
     *
     * @param marshalledPublicKey Marshalled public key
     * @return Fingerprint consisting of Base64 encoding of first four bytes from SHA-256 digest of public key
     * @throws GeneralSecurityException Thrown on failures to get Message Digest for fingerprinting
     */
    @Override
    public String getFingerprint(final byte[] marshalledPublicKey) throws GeneralSecurityException {
        final MessageDigest messageDigest = getMessageDigest();
        final byte[] digest = messageDigest.digest(marshalledPublicKey);
        final byte[] fingerprintDigest = Arrays.copyOfRange(digest, 0, FINGERPRINT_DIGEST_LENGTH);
        return ENCODER.encodeToString(fingerprintDigest);
    }

    private MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(DIGEST_ALGORITHM);
    }
}
