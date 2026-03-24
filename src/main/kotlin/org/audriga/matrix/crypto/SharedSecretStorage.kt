package org.audriga.matrix.crypto

import HkdfSha256
import org.matrix.android.sdk.api.crypto.SSSS_ALGORITHM_AES_HMAC_SHA2
import org.matrix.android.sdk.api.extensions.orFalse
import org.matrix.android.sdk.api.session.securestorage.EncryptedSecretContent
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.android.sdk.api.session.securestorage.SharedSecretStorageError
import org.matrix.android.sdk.api.session.securestorage.SsssKeySpec
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and
import kotlin.io.encoding.Base64

class SharedSecretStorage {
    companion object {

        //Copied from DefaultSharedSecretStorageService
        @Throws
        fun encryptAesHmacSha2(
            secretKey: SsssKeySpec,
            secretName: String,
            clearDataBase64: String,
            providedIv: IvParameterSpec? = null,
        ): EncryptedSecretContent {
            secretKey as RawBytesKeySpec
            val secretNameBytes = secretName.toByteArray()
            val privateKeyBytes = secretKey.privateKey
            println("privateKeyBytes: ${privateKeyBytes.map { b -> b.toInt() and 0xFF }.joinToString(", ")} (${privateKeyBytes.size} bytes), hex: ${privateKeyBytes.toHexString()}")
            val pseudoRandomKey = HkdfSha256.deriveSecret(
                privateKeyBytes,
                ByteArray(32) { 0.toByte() },
                secretNameBytes,
                64
            )

            // The first 32 bytes are used as the AES key, and the next 32 bytes are used as the MAC key
            val aesKey = pseudoRandomKey.copyOfRange(0, 32)
            val macKey = pseudoRandomKey.copyOfRange(32, 64)


            println("aesKey = ${aesKey.map { b -> b.toInt() and 0xFF }.joinToString(", ")} (${aesKey.size} bytes), hex ${aesKey.toHexString()}\n" +
                    "macKey = ${macKey.map { b -> b.toInt() and 0xFF }.joinToString(", ")} (${macKey.size} bytes), hex ${macKey.toHexString()}")

            val secureRandom = SecureRandom()
            val iv = ByteArray(16)
            secureRandom.nextBytes(iv)

            // clear bit 63 of the salt to stop us hitting the 64-bit counter boundary
            // (which would mean we wouldn't be able to decrypt on Android). The loss
            // of a single bit of salt is a price we have to pay.
            iv[9] = iv[9] and 0x7f
            println("Iv = ${iv.map { b -> b.toInt() and 0xFF}.joinToString(", ")} (${iv.size} bytes), hex ${iv.toHexString()}\n")

            val cipher = Cipher.getInstance("AES/CTR/NoPadding")

            val secretKeySpec = SecretKeySpec(aesKey, "AES")
            val ivParameterSpec = providedIv ?: IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)
            // secret are not that big, just do Final
            val clearDataBytes = clearDataBase64.toByteArray()
            val cipherBytes = cipher.doFinal(clearDataBytes)
            require(cipherBytes.isNotEmpty())

            println("SecretName: \"$secretName\", ${secretNameBytes.map { b -> b.toInt() and 0xFF }.joinToString(", ")} (${secretNameBytes.size} bytes), hex: ${secretNameBytes.toHexString()}")
            println("Plaintext: \"$clearDataBase64\", ${clearDataBytes.map { b -> b.toInt() and 0xFF }.joinToString(", ")} (${clearDataBytes.size} bytes), hex: ${clearDataBytes.toHexString()}")
            val macKeySpec = SecretKeySpec(macKey, "HmacSHA256")
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(macKeySpec)
            val digest = mac.doFinal(cipherBytes)

            return EncryptedSecretContent(
                ciphertext = cipherBytes.toBase64NoPadding(),
                initializationVector = iv.toBase64NoPadding(),
                mac = digest.toBase64NoPadding()
            )
        }

        @JvmStatic
        fun checkRecoveryKey(
            decodedSpec: RawBytesKeySpec,
            algorithm: String?,
            iv: String?,
            mac: String?
        ): Boolean {
            if (!algorithm.equals(SSSS_ALGORITHM_AES_HMAC_SHA2)) {
                return false
            }
            val empty = ByteArray(32) { 0.toByte() }.toString(Charsets.UTF_8) // initialized to zero
            val (_, mac1, _, _) = encryptAesHmacSha2(
                decodedSpec,
                "",
                empty,
                IvParameterSpec(Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(iv!!))
            )
            val recoveryKeyCorrect = mac?.replace("=", "").equals(mac1)
            return recoveryKeyCorrect
        }


        // Copied from internal DefaultSharedSecretStorageService.kt / org.matrix.android.sdk.internal.crypto.secrets
        @JvmStatic
        fun decryptAesHmacSha2(secretKey: RawBytesKeySpec, secretName: String, cipherContent: EncryptedSecretContent): String {
            // Note: original function header uses matrix.android.sdk.api.session.securestorage.SsssKeySpec,
            // but then casts to RawBytesKeySpec anyway
            val pseudoRandomKey = HkdfSha256.deriveSecret(
                secretKey.privateKey,
                ByteArray(32) { 0.toByte() },
                secretName.toByteArray(),
                64
            )

            // The first 32 bytes are used as the AES key, and the next 32 bytes are used as the MAC key
            val aesKey = pseudoRandomKey.copyOfRange(0, 32)
            val macKey = pseudoRandomKey.copyOfRange(32, 64)

            val iv = cipherContent.initializationVector?.fromBase64() ?: ByteArray(16)

            val cipherRawBytes = cipherContent.ciphertext?.fromBase64() ?: throw SharedSecretStorageError.BadCipherText

            // Check Signature
            val macKeySpec = SecretKeySpec(macKey, "HmacSHA256")
            val mac = Mac.getInstance("HmacSHA256").apply { init(macKeySpec) }
            val digest = mac.doFinal(cipherRawBytes)

            if (!cipherContent.mac?.fromBase64()?.contentEquals(digest).orFalse()) {
                throw SharedSecretStorageError.BadMac
            }

            val cipher = Cipher.getInstance("AES/CTR/NoPadding")

            val secretKeySpec = SecretKeySpec(aesKey, "AES")
            val ivParameterSpec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)
            // secret are not that big, just do Final
            val decryptedSecret = cipher.doFinal(cipherRawBytes)

            require(decryptedSecret.isNotEmpty())

            return String(decryptedSecret, Charsets.UTF_8)
        }
    }
}