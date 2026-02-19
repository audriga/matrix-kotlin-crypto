import org.matrix.android.sdk.api.extensions.orFalse
import org.matrix.android.sdk.api.session.securestorage.EncryptedSecretContent
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.android.sdk.api.session.securestorage.SharedSecretStorageError
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// Copied from internal DefaultSharedSecretStorageService.kt / org.matrix.android.sdk.internal.crypto.secrets
internal fun decryptAesHmacSha2(secretKey: RawBytesKeySpec, secretName: String, cipherContent: EncryptedSecretContent): String {
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
