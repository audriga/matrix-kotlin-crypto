package org.audriga.matrix.crypto.ssss

import keybackup.MoshiProvider
import org.audriga.matrix.crypto.SharedSecretStorage.Companion.encryptAesHmacSha2
import org.matrix.android.sdk.api.crypto.SSSS_ALGORITHM_AES_HMAC_SHA2
import org.matrix.android.sdk.api.session.crypto.keysbackup.computeRecoveryKey
import org.matrix.android.sdk.api.session.securestorage.EncryptedSecretContent
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.android.sdk.api.session.securestorage.SsssKeySpec
import java.security.SecureRandom
import java.util.*

/**
 * Wrapper object for the actual symmetric key used to encrypt/ decrypt the secret account data (the SSSS keys),
 * and the "recovery key" representation of it. Not to be confused with SecretStorageKeyContent, which is info about
 * the secret storage key uploaded (unencrypted) to the account data
 */
data class SecretStorageKey(
    val sssKeySpec: RawBytesKeySpec,
    val recoveryKey: String,
) {
    companion object {
        @JvmStatic
        fun generateSecretStorageKey() = generateSecretStorageKey(null)

        /**
         * Generates a secret storage key, and outputs it alongside it's corresponding recovery key representation
         * @param key existing secret storage key. If given will only compute recovery key based on given key.
         */
        @JvmStatic
        fun generateSecretStorageKey(key: SsssKeySpec?): SecretStorageKey {
            val bytes = (key as? RawBytesKeySpec)?.privateKey
                ?: ByteArray(32).also {
                    SecureRandom().nextBytes(it)
                }

            val ssssKeySpec = RawBytesKeySpec(bytes)
            val recoveryKey = computeRecoveryKey(bytes)
            return SecretStorageKey(ssssKeySpec, recoveryKey)
        }
        internal fun String.formatRecoveryKey(): String = this.split("(?<=\\G....)".toRegex()).joinToString(" ")

    }
    fun getFormattedRecoveryKey(): String = recoveryKey.formatRecoveryKey()
}

class SecretStorageService {
    companion object {
        const val KEY_ID_BASE = "m.secret_storage.key"
        const val DEFAULT_KEY_ID = "m.secret_storage.default_key"


        @JvmStatic
        /**
         * Creates the data that will later be uploaded to `m.secret_storage.key.{keyId}`.
         * Namely, this creates an iv and mac according to the spec, and also returns the body that should be included
         * in the corresponding account data upload.
         * See also https://spec.matrix.org/latest/client-server-api/#msecret_storagev1aes-hmac-sha2
         */
        public fun createSecretStorageKeyVerificationInfo(ssssKeySpec: RawBytesKeySpec): SecretStorageKeyVerificationInfo {
            val zeroClearData = ByteArray(32) { 0.toByte() }.toString(Charsets.UTF_8) // initialized to zero
            val (_, mac, _, initializationVector) = encryptAesHmacSha2(
                ssssKeySpec,
                "",
                zeroClearData
            )
            val uploadContent = mapOf(
                "algorithm" to SSSS_ALGORITHM_AES_HMAC_SHA2,
                "iv" to "$initializationVector",
                "mac" to "$mac"
            )

            return SecretStorageKeyVerificationInfo(initializationVector, mac, uploadContent)
        }


        /**
         * Spec does not mandate exact form of the keyId of `m.secret_storage.key.{keyId}`.
         * UUID is a good choice. This is just a convenience method.
         */
        @JvmStatic
        fun generateKeyId() = UUID.randomUUID().toString()

        @JvmStatic
        fun encryptKeyForAccountDataStorage(
            ssssKeySpec: SsssKeySpec,
            name: String,
            secretBase64: String,
            keyId: String
        ): Map<String, HashMap<String, EncryptedSecretContent>> {
            val encryptedContents = HashMap<String, EncryptedSecretContent>()
            encryptAesHmacSha2(ssssKeySpec, name, secretBase64).let {
                encryptedContents[keyId] = it
            }
            val uploadContent = mapOf("encrypted" to encryptedContents)
            return uploadContent
        }

    }

}


data class SecretStorageKeyVerificationInfo(
    val iv: String?,
    val mac: String?,
    val uploadContent: Map<String, String>
) {
    fun uploadContentAsJson(): String = MoshiProvider.providesMoshi().adapter(Map::class.java).toJson(uploadContent)
}
