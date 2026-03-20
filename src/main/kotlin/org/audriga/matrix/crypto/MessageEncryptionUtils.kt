package org.audriga.matrix.crypto

import org.matrix.rustcomponents.sdk.crypto.EncryptionSettings
import org.matrix.rustcomponents.sdk.crypto.EventEncryptionAlgorithm
import org.matrix.rustcomponents.sdk.crypto.HistoryVisibility

class MessageEncryptionUtils {
    companion object {
        @JvmStatic
        fun defaultEncryptionSettings(): EncryptionSettings =  EncryptionSettings(
            algorithm = EventEncryptionAlgorithm.MEGOLM_V1_AES_SHA2,
            onlyAllowTrustedDevices = false,
            rotationPeriod = 604800000.toULong(),
            rotationPeriodMsgs = 100.toULong(),
            historyVisibility = HistoryVisibility.SHARED,
            errorOnVerifiedUserProblem = false,
        )
    }
}