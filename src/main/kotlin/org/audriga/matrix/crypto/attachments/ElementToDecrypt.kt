package org.audriga.matrix.crypto.attachments

import org.matrix.android.sdk.api.session.crypto.model.EncryptedFileInfo

// Function copied from org.matrix.android.sdk.api.session.crypto.attachments.ElementToDecrypt
fun EncryptedFileInfo.toElementToDecrypt(): ElementToDecrypt? {
    if (isValid()) {
        return ElementToDecrypt(
            iv = this.iv ?: "",
            k = this.key?.k ?: "",
            sha256 = this.hashes?.get("sha256") ?: ""
        )
    }
    return null
}

data class ElementToDecrypt (
    val iv: String,
    val k: String,
    val sha256: String,
)