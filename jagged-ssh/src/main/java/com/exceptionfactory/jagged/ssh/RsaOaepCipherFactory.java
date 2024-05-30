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

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Objects;

/**
 * RSA OAEP Cipher Factory with algorithm selection matching age-ssh implementation
 */
class RsaOaepCipherFactory {
    private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPPadding";

    private static final String DIGEST_ALGORITHM = "SHA-256";

    private static final String MGF_ALGORITHM = "MGF1";

    private static final AlgorithmParameterSpec ALGORITHM_PARAMETER_SPEC = new MGF1ParameterSpec(DIGEST_ALGORITHM);

    private static final byte[] ENCODING_INPUT = SshRsaRecipientIndicator.ENCODING_LABEL.getIndicator().getBytes(StandardCharsets.UTF_8);

    private static final PSource ENCODING_SOURCE = new PSource.PSpecified(ENCODING_INPUT);

    /**
     * Get RSA OAEP initialized cipher based on Cipher Mode and Key
     *
     * @param cipherMode Cipher mode for encryption or decryption
     * @param key Public or private key
     * @return Initialized Cipher
     * @throws GeneralSecurityException Thrown on initialization failures
     */
    Cipher getInitializedCipher(final CipherMode cipherMode, final Key key) throws GeneralSecurityException {
        Objects.requireNonNull(cipherMode, "Cipher Mode required");
        Objects.requireNonNull(key, "Key required");

        final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

        final OAEPParameterSpec parameterSpec = new OAEPParameterSpec(
                DIGEST_ALGORITHM,
                MGF_ALGORITHM,
                ALGORITHM_PARAMETER_SPEC,
                ENCODING_SOURCE
        );

        cipher.init(cipherMode.mode, key, parameterSpec);
        return cipher;
    }

    enum CipherMode {
        DECRYPT(Cipher.DECRYPT_MODE),

        ENCRYPT(Cipher.ENCRYPT_MODE);

        private final int mode;

        CipherMode(final int mode) {
            this.mode = mode;
        }
    }
}
