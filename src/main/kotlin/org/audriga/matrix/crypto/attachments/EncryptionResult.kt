/*
 * Copyright 2020 The Matrix.org Foundation C.I.C.
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

package org.audriga.matrix.crypto.attachments

import org.matrix.android.sdk.api.session.crypto.model.EncryptedFileInfo

// Originally copied from/ based on org.matrix.android.sdk.internal.crypto.attachments
/**
 * Define the result of an encryption file.
 */
internal data class EncryptionResult(
    val encryptedFileInfo: EncryptedFileInfo,
    val encryptedByteArray: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptionResult

        if (encryptedFileInfo != other.encryptedFileInfo) return false
        if (!encryptedByteArray.contentEquals(other.encryptedByteArray)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encryptedFileInfo.hashCode()
        result = 31 * result + encryptedByteArray.contentHashCode()
        return result
    }
}