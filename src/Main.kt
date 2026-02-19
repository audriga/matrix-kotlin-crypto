import org.matrix.android.sdk.api.Matrix
import org.matrix.android.sdk.api.extensions.orFalse
import org.matrix.android.sdk.api.session.crypto.crosssigning.KEYBACKUP_SECRET_SSSS_NAME
//import org.matrix.android.sdk.api.MatrixConfiguration
import org.matrix.android.sdk.api.session.crypto.keysbackup.BackupRecoveryKey
import org.matrix.android.sdk.api.session.securestorage.EncryptedSecretContent
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.android.sdk.api.session.securestorage.SharedSecretStorageError
import org.matrix.android.sdk.api.session.securestorage.SsssKeySpec
import org.matrix.rustcomponents.sdk.crypto.ProgressListener as RustProgressListener
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine
// Todo: Potentially get rid of matrix-android-sdk2 and only use rustcomponents sdk directly.
//import org.matrix.rustcomponents.sdk.crypto.BackupRecoveryKey
//import org.matrix.rustcomponents.sdk.crypto.MegolmV1BackupKey
import org.matrix.rustcomponents.sdk.crypto.version
import uniffi.matrix_sdk_crypto.DecryptionSettings
import uniffi.matrix_sdk_crypto.TrustRequirement
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.io.ByteArrayOutputStream
import java.lang.Thread.sleep
import java.nio.ByteBuffer
import kotlin.io.encoding.Base64
import kotlin.math.ceil
import kotlin.system.exitProcess

fun main() {
    val version = version()
    val cryptoVersion = Matrix.getCryptoVersion(longFormat = true)
    println("version, $version!")
    println("cryptoVersion, $cryptoVersion!")

    val aliceRecoveryKey = "EsTd Ptqg Qakz Xz3R 4276 cT5w GDrW TYXU wBUd wjyj xWPm 92e9";

    // Note: Came across `BackupRecoveryKey.fromBase58(backupRecoveryKey)`
    //   via `org.matrix.rustcomponents.sdk.crypto.BackupRecoveryKey.Companion.fromBase58`
    //   or directly `import org.matrix.android.sdk.api.session.crypto.keysbackup.BackupRecoveryKey.Companion.fromBase58`.
    //   This can be a bit confusing, since the "Recovery Key" shown by clients is also encoded in base58, and this
    //   function would successfully decode `aliceRecoveryKey`. However, `aliceRecoveryKey` is the encoded private key
    //   for the SSSS store, which can then be used to decrypt the backup key.
    val keyBackupKeyName = KEYBACKUP_SECRET_SSSS_NAME // "m.megolm_backup.v1"
    val ssssPrivateKeySpec = RawBytesKeySpec.fromRecoveryKey(aliceRecoveryKey)
    if (ssssPrivateKeySpec == null) {
        println("Decoded sssPrivateKeySpec is null!")
        exitProcess(1)
    }

    // Values from Alice's account data:
    /*
          {
        "type": "m.megolm_backup.v1",
        "content": {
          "encrypted": {
            "w5OUcEWRgGMYwQwA5npQZhSAal24ZZ6g": {
              "iv": "fBd5a5IXo8M8oxvTVrFUfw==",
              "ciphertext": "EPNKKMNe63qtiKLePI9eBPFy0hEWU/u5H8ArpxM2qva9u0Fu+7Y5Lbv2Gw==",
              "mac": "EryWMN0JnJ3+MneHo4LJ3EOH0/XAjsGkOexZcEKJebk="
            }
          }
        }
      },
     */
    val secretContent = EncryptedSecretContent(
        initializationVector = "fBd5a5IXo8M8oxvTVrFUfw==",
        ciphertext = "EPNKKMNe63qtiKLePI9eBPFy0hEWU/u5H8ArpxM2qva9u0Fu+7Y5Lbv2Gw==",
        mac = "EryWMN0JnJ3+MneHo4LJ3EOH0/XAjsGkOexZcEKJebk=",
    )

    val decryptedBackupKey = decryptAesHmacSha2(ssssPrivateKeySpec, keyBackupKeyName, secretContent)
    println(decryptedBackupKey)

    // TODO see also QuadSTests https://github.com/matrix-org/matrix-android-sdk2/blob/a37dfa83cbe03cf74951d66a860a70b49484e32f/matrix-sdk-android/src/androidTest/java/org/matrix/android/sdk/internal/crypto/ssss/QuadSTests.kt#L124

    val decodedRecoveryKey = BackupRecoveryKey.fromBase64(decryptedBackupKey)
    println(decodedRecoveryKey.megolmV1PublicKey().backupAlgorithm)

    // Some megolm session gotten via room_keys/keys api call
    /*
    {
  "rooms": {
    "!CkmkaydvMtvVXXukVn:ZetaHorologii": {
      "sessions": {
        "06pJO2EEEkWxans9viRZllaagZQO/XV4K2/Iuz0RMTQ": {
          "first_message_index": 0,
          "forwarded_count": 0,
          "is_verified": false,
          "session_data": {
            "ciphertext": "achSSv18s4DHbUS5+NxlNrcyDjzZk6mFlDmrOPOeRhulRkAcAQUGNNRhgacO5okYxG6uOmH3rWuVUOwXB1JLknaMN9O4jBNrgmHkQjekujT7SQaYFJhIf/YQQy5EVxOeI0S9vpPdhVVf/ekl5X6XZhL727P98Uscf2o4094UHdlA2g6upYU/FNRejzZ3TA88UWNOJM7v8Sg4cttOMchUJLgOp6vAl2tcbMDykTDO4iSIpJX3ai5LVhIjLs4Ygr2VFp41zgWBOU8CW7hFSZPg1UBHCw7yy3IuwxOKs3zTOkblU2T2y3ovOLyuoYisDX9Zi7l2mvQsq9uNSxzt6YMYDT4h6azuJTNnZ/RxBznUaTgap0n+C0Vqt8C/gkeKz44lLRq8HiG8bKoI6b2ViwbiE+tN0G30nHdY0dykZUh/rE2x98z3iotP02OvQoY0ixXzRpEif/ONbHBO7Cbq3X1GGH57dFHJc6eIRLplnUzzHuJ8HSit5caRLcr6UqLSIFQMZE5s22N1Ve1t9FKs7FGHeRsLEl90TJEo0uL5tUExUDQQLVFrIsH2GTy521zdCxn9MXE30cKgAhOJwRifLra2eqme1jlARNmB8pkmpTzRV7KhrGLcNd4xa/L2UUWQtB2rCM8YCs41JXMQZQ5XbhRCFA",
            "ephemeral": "8TRPnq4uaEZ8PQr6pklIfbxtjeogxY0bcraMjmACsns",
            "mac": "rdYvArAPNec"
          }
        },

     */
    val decryptedMegolmSession = decodedRecoveryKey.decryptV1(
        ephemeralKey = "8TRPnq4uaEZ8PQr6pklIfbxtjeogxY0bcraMjmACsns",
        mac = "rdYvArAPNec",
        ciphertext = "achSSv18s4DHbUS5+NxlNrcyDjzZk6mFlDmrOPOeRhulRkAcAQUGNNRhgacO5okYxG6uOmH3rWuVUOwXB1JLknaMN9O4jBNrgmHkQjekujT7SQaYFJhIf/YQQy5EVxOeI0S9vpPdhVVf/ekl5X6XZhL727P98Uscf2o4094UHdlA2g6upYU/FNRejzZ3TA88UWNOJM7v8Sg4cttOMchUJLgOp6vAl2tcbMDykTDO4iSIpJX3ai5LVhIjLs4Ygr2VFp41zgWBOU8CW7hFSZPg1UBHCw7yy3IuwxOKs3zTOkblU2T2y3ovOLyuoYisDX9Zi7l2mvQsq9uNSxzt6YMYDT4h6azuJTNnZ/RxBznUaTgap0n+C0Vqt8C/gkeKz44lLRq8HiG8bKoI6b2ViwbiE+tN0G30nHdY0dykZUh/rE2x98z3iotP02OvQoY0ixXzRpEif/ONbHBO7Cbq3X1GGH57dFHJc6eIRLplnUzzHuJ8HSit5caRLcr6UqLSIFQMZE5s22N1Ve1t9FKs7FGHeRsLEl90TJEo0uL5tUExUDQQLVFrIsH2GTy521zdCxn9MXE30cKgAhOJwRifLra2eqme1jlARNmB8pkmpTzRV7KhrGLcNd4xa/L2UUWQtB2rCM8YCs41JXMQZQ5XbhRCFA"
    )

    println(decryptedMegolmSession)

    // Note, when matrix-android-sdk2 internally decrypts a Megolm session,
    // it parses it to a SessionData object (see copied code snippet below).
    // However, we cannot do this here without copying the relevant classes, since these classes are internal.
    // ```kotlin
    // val moshi = MoshiProvider.providesMoshi()
    // val adapter = moshi.adapter(MegolmSessionData::class.java)
    // val sessionBackupData = adapter.fromJson(decryptedMegolmSession)
    // ```
    val rustOmlMachine = RustOmlMachine("@alice:ZetaHorologii", "migDevice", "/tmp/olmMachine", null)

    // importDecryptedRoomKeys Expects the serialized form of MegolmSessionData from internal class
    // package org.matrix.android.sdk.internal.crypto
    // This should be the same as the decrypted session, with additional keys for sessionId and roomId,
    // see decryptKeyBackupData in RustKeyBackupService.kt of matrix-android-sdk2 .
    // Todo: This appears to be loosing info like first_message_index or forwarded_count. Does the olmMachine not need
    //  this? Do we need to check ourselves if we can decrypt a given message with a given session?
    val roomId = "!CkmkaydvMtvVXXukVn:ZetaHorologii"
    val encodedKey = "[" + decryptedMegolmSession.dropLast(1) +
            ",\"room_id\":\"$roomId\"" +
            ",\"session_id\":\"06pJO2EEEkWxans9viRZllaagZQO/XV4K2/Iuz0RMTQ\"" +
            "}]"
    val rustListener = object : RustProgressListener {
        override fun onProgress(progress: Int, total: Int) {
          println("Rust is processing keys $progress | $total")
        }
    }
    rustOmlMachine.importDecryptedRoomKeys(encodedKey,rustListener)
    println("Is the previous call async?")
//    sleep(1000)

    // Decrypting a message event that is encrypted with the session we just imported
    val event = """{
      "type": "m.room.encrypted",
      "sender": "@bob:ZetaHorologii",
      "content": {
        "algorithm": "m.megolm.v1.aes-sha2",
        "ciphertext": "AwgAEvADkU4yrylcCGcDNjW5sjQQVMmjo0xThpbPehiYVlxN3GFHR1QbB98cluK7pX9nKr3MlJufyaa9uBWLyCx8Qliw2I6cThWMMzJW1Sl7UskWb1OFDIQ06QITUiEm6dX2ctgertiMqoFlKnJO4zMdxHGVJWev5JNe+7GO1fB680lK5z+dgwuJRzSenGMWkvWyzFBtd3Fqm8+0JDLWgOItkm+fnHhTPj4WhLSLcxaFiL59kigH2BVTt5qDb4GrWWBlrFLD+2i0q1Yeh9N7eTmxTP7TkBSmspo4LdW4TA2WyQtlXuHPjb3Tk4IvUM8ZUiuLbW1tiv9XYXfR9phY8X67LEngLKWIKbJaEk4+gG/85YW7DuVWtXOSfHHpE73EFM58c5mKx5QTA8mDDRvdemKSEtf/U5sO2+DL0NwFn6Ysdpl+4fZSJ8A/Chb+9i9hjzd/AJKDczAJf94ndhhEwXzv6tmhkxTfm+sg+xn0BLBDTcBZsjPxcRlRoOdhXZRE452rB13zRzybgSLLFFEXRmiS2ATTiWLPdt17yHIJSUvT3a6zUjrgyyr9b9du3+9XExc7eJc090ZjQNcr0Iv6IdYNhDNpDhl0Nm0PNVZF3w4QLmpGyV71ixNZYmYSGgZ1maBLzzLVdV7gdtvxS3IDjOx4KUZo8nY8i5TjLk1pAtJ9w47p+G4CKKPnUGBUwcH3qiegPklayKIBRdU7n5vcf9caH51yPDd6GRQx/e9vvgv9Kl2EfhUKc3JSuJd0Bw",
        "device_id": "UHCPTGMSVS",
        "sender_key": "fDxrjAKZ0ZDyunTVJDbQD9jSTwcZw40OrMYOdmKuHjY",
        "session_id": "06pJO2EEEkWxans9viRZllaagZQO/XV4K2/Iuz0RMTQ"
      },
      "room_id": "!CkmkaydvMtvVXXukVn:ZetaHorologii",
      "origin_server_ts": 1762185350129,
      "unsigned": {
        "age": 9305016934,
        "m.relations": {
          "m.reference": {
            "chunk": [
              {
                "event_id": "${'$'}Ho5l3WiVEm5cu9ta3b0oJFhAgIHXQggVyf7WV8KQ4ok"
              },
              {
                "event_id": "${'$'}NgFdXdKYdPPhAjoTouw0x-VPSEij34FM5YG7sAfhpBU"
              },
              {
                "event_id": "${'$'}ssmNxFbGnVCKXfmuO_IGU5KVP4oz0HfXkFhipZuklGk"
              }
            ]
          }
        }
      },
      "event_id": "${'$'}kNIvOS5IjkbcQ_a5GmT2tWppPrexQc2uQq5OYhJPqqI",
      "user_id": "@bob:ZetaHorologii",
      "age": 9305016934
    }"""

    val (clearEvent, senderCurve25519Key, claimedEd25519Key, forwardingCurve25519Chain, shieldState) = rustOmlMachine.decryptRoomEvent(
        event = event,
        roomId = roomId,
        handleVerificationEvents = false,
        strictShields = false,
        decryptionSettings = DecryptionSettings(TrustRequirement.UNTRUSTED)
    )
    println(clearEvent)

    //  I can decrypt the same event twice, which means the olmMachine is keeping track of previous states
    val (clearEvent2, _, _, _, _) = rustOmlMachine.decryptRoomEvent(
        event = event,
        roomId = roomId,
        handleVerificationEvents = false,
        strictShields = false,
        decryptionSettings = DecryptionSettings(TrustRequirement.UNTRUSTED)
    )
    println(clearEvent2)
}

// Copied from DefaultSharedSecretStorageService.kt
private fun decryptAesHmacSha2(secretKey: SsssKeySpec, secretName: String, cipherContent: EncryptedSecretContent): String {
    secretKey as RawBytesKeySpec
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

//Copy paste from org.matrix.android.sdk.internal.crypto.tools.HkdfSha256
internal object HkdfSha256 {

    fun deriveSecret(inputKeyMaterial: ByteArray, salt: ByteArray?, info: ByteArray, outputLength: Int): ByteArray {
        return expand(extract(salt, inputKeyMaterial), info, outputLength)
    }

    /**
     * HkdfSha256-Extract(salt, IKM) -> PRK.
     *
     * @param salt optional salt value (a non-secret random value);
     * if not provided, it is set to a string of HashLen (size in octets) zeros.
     * @param ikm input keying material
     */
    private fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val mac = initMac(salt ?: ByteArray(HASH_LEN) { 0.toByte() })
        return mac.doFinal(ikm)
    }

    /**
     * HkdfSha256-Expand(PRK, info, L) -> OKM.
     *
     * @param prk a pseudorandom key of at least HashLen bytes (usually, the output from the extract step)
     * @param info optional context and application specific information (can be empty)
     * @param outputLength length of output keying material in bytes (<= 255*HashLen)
     * @return OKM output keying material
     */
    private fun expand(prk: ByteArray, info: ByteArray = ByteArray(0), outputLength: Int): ByteArray {
        require(outputLength <= 255 * HASH_LEN) { "outputLength must be less than or equal to 255*HashLen" }

        /*
          The output OKM is calculated as follows:
          Notation | -> When the message is composed of several elements we use concatenation (denoted |) in the second argument;


           N = ceil(L/HashLen)
           T = T(1) | T(2) | T(3) | ... | T(N)
           OKM = first L octets of T

           where:
           T(0) = empty string (zero length)
           T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
           T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
           T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
           ...
         */
        val n = ceil(outputLength.toDouble() / HASH_LEN.toDouble()).toInt()

        var stepHash = ByteArray(0) // T(0) empty string (zero length)

        val generatedBytes = ByteArrayOutputStream() // ByteBuffer.allocate(Math.multiplyExact(n, HASH_LEN))
        val mac = initMac(prk)
        for (roundNum in 1..n) {
            mac.reset()
            val t = ByteBuffer.allocate(stepHash.size + info.size + 1).apply {
                put(stepHash)
                put(info)
                put(roundNum.toByte())
            }
            stepHash = mac.doFinal(t.array())
            generatedBytes.write(stepHash)
        }

        return generatedBytes.toByteArray().sliceArray(0 until outputLength)
    }

    private fun initMac(secret: ByteArray): Mac {
        val mac = Mac.getInstance(HASH_ALG)
        mac.init(SecretKeySpec(secret, HASH_ALG))
        return mac
    }

    private const val HASH_LEN = 32
    private const val HASH_ALG = "HmacSHA256"
}

// Replaces the extension function used by the top level matrix library, since
// `org.matrix.android.sdk.api.util.fromBase64` requires android
fun String.fromBase64(): ByteArray {
    return Base64.decode(this)
}
