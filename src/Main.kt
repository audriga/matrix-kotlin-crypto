@file:Suppress("SameParameterValue")

import org.matrix.android.sdk.api.session.crypto.crosssigning.KEYBACKUP_SECRET_SSSS_NAME
// Todo: We currently solely use a few parsing methods and data classes.
//  Potentially copy paste them in the codebase (like we did for some internal utils we needed)
//  And remove dependency to matrix-android-sdk2 (only using rustcomponents sdk directly).
import org.matrix.rustcomponents.sdk.crypto.BackupRecoveryKey
// Note: Corresponding matrix-android-sdk2 import: org.matrix.android.sdk.api.session.crypto.keysbackup.BackupRecoveryKey
import org.matrix.android.sdk.api.session.securestorage.EncryptedSecretContent
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.rustcomponents.sdk.crypto.EncryptionSettings
import org.matrix.rustcomponents.sdk.crypto.EventEncryptionAlgorithm
import org.matrix.rustcomponents.sdk.crypto.HistoryVisibility
import org.matrix.rustcomponents.sdk.crypto.MegolmV1BackupKey
import org.matrix.rustcomponents.sdk.crypto.version
import uniffi.matrix_sdk_crypto.DecryptionSettings
import uniffi.matrix_sdk_crypto.TrustRequirement
import kotlin.system.exitProcess
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine
import org.matrix.rustcomponents.sdk.crypto.ProgressListener as RustProgressListener

fun main() {
    val version = version()
    // Note, could also get additional version info via Matrix.getCryptoVersion(longFormat = true)
    println("Rust SDK version, $version!")

    val roomId = "!CkmkaydvMtvVXXukVn:ZetaHorologii"
    val rustOlmMachine = decryptPoC(roomId)
    encryptWithRecoveredMegolmSession(rustOlmMachine, roomId)
}

private fun encryptWithRecoveredMegolmSession(rustOlmMachine: RustOmlMachine, roomId: String) {
    val users = listOf("@bob:ZetaHorologii")
    val missingSessions = rustOlmMachine.getMissingSessions(users)
    println(missingSessions)
    // Via PrepareToEncryptUseCase.kt / CryptoRoomInfo.kt
    val settings = EncryptionSettings(
        algorithm = EventEncryptionAlgorithm.MEGOLM_V1_AES_SHA2,
        onlyAllowTrustedDevices = false,
        rotationPeriod = 604800000.toULong(),
        rotationPeriodMsgs = 100.toULong(),
        historyVisibility = HistoryVisibility.SHARED,
        errorOnVerifiedUserProblem = false,
    )
    val shareRoomKeyRequests = rustOlmMachine.shareRoomKey(roomId, users, settings)
    println(shareRoomKeyRequests)
    // Returns error "Session wasn't created nor shared", if shareRoomKey was not previously called.
    val encryptedEvent = rustOlmMachine.encrypt(
        roomId,
        "m.room.message",
        """
            {
             "msgtype": "m.text",
             "body": "Encrypted hi from API"
            }
        """.trimIndent(),
    )
    println(encryptedEvent)
}

private fun decryptPoC(roomId: String): RustOmlMachine {
    val ssssPrivateKeySpec = decodeAliceSSSSRecoveryKey()

    val decodedRecoveryKey = decryptAliceMegolmBackupKey(ssssPrivateKeySpec)
    val decryptedMegolmSession = decryptSampleMegolmSession(decodedRecoveryKey)

    val rustOmlMachine = createOlmMachineAndImportDecryptedSession(decryptedMegolmSession, roomId)

    decryptSomeRoomEvent(rustOmlMachine, roomId)
    return rustOmlMachine
}

private fun decryptSomeRoomEvent(rustOmlMachine: RustOmlMachine, roomId: String) {
    // Decrypting a message event that is encrypted with the session we just imported
    val event = $$"""{
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
                "event_id": "$Ho5l3WiVEm5cu9ta3b0oJFhAgIHXQggVyf7WV8KQ4ok"
              },
              {
                "event_id": "$NgFdXdKYdPPhAjoTouw0x-VPSEij34FM5YG7sAfhpBU"
              },
              {
                "event_id": "$ssmNxFbGnVCKXfmuO_IGU5KVP4oz0HfXkFhipZuklGk"
              }
            ]
          }
        }
      },
      "event_id": "$kNIvOS5IjkbcQ_a5GmT2tWppPrexQc2uQq5OYhJPqqI",
      "user_id": "@bob:ZetaHorologii",
      "age": 9305016934
    }"""

    val decryptedEvent = rustOmlMachine.decryptRoomEvent(
        event = event,
        roomId = roomId,
        handleVerificationEvents = false,
        strictShields = false,
        decryptionSettings = DecryptionSettings(TrustRequirement.UNTRUSTED)
    )
    println(decryptedEvent.clearEvent)

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

private fun createOlmMachineAndImportDecryptedSession(
    decryptedMegolmSession: String,
    roomId: String
): RustOmlMachine {
    val rustOmlMachine = RustOmlMachine("@alice:ZetaHorologii", "migDevice", "/tmp/olmMachine", null)

    // importDecryptedRoomKeys Expects the serialized form of MegolmSessionData from internal class
    // package org.matrix.android.sdk.internal.crypto
    // This should be the same as the decrypted session, with additional keys for sessionId and roomId,
    // see decryptKeyBackupData in RustKeyBackupService.kt of matrix-android-sdk2 .
    // Todo: This appears to be loosing info like first_message_index or forwarded_count. Does the olmMachine not need
    //  this? Do we need to check ourselves if we can decrypt a given message with a given session?
    val encodedKey = "[" + decryptedMegolmSession.dropLast(1) +
            ",\"room_id\":\"$roomId\"" +
            ",\"session_id\":\"06pJO2EEEkWxans9viRZllaagZQO/XV4K2/Iuz0RMTQ\"" +
            "}]"
    val rustListener = object : RustProgressListener {
        override fun onProgress(progress: Int, total: Int) {
            println("Rust is processing keys $progress | $total")
        }
    }
    rustOmlMachine.importDecryptedRoomKeys(encodedKey, rustListener)
    println("Is the previous call async?")
//    sleep(1000)
    return rustOmlMachine
}

private fun decryptSampleMegolmSession(decodedRecoveryKey: BackupRecoveryKey): String {
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
    return decryptedMegolmSession

}

private fun decryptAliceMegolmBackupKey(ssssPrivateKeySpec: RawBytesKeySpec): BackupRecoveryKey {
    val keyBackupKeyName = KEYBACKUP_SECRET_SSSS_NAME // "m.megolm_backup.v1"
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
    val publicPartOfMegolmV1BackupKey: MegolmV1BackupKey = decodedRecoveryKey.megolmV1PublicKey()
    println(publicPartOfMegolmV1BackupKey.backupAlgorithm)
    return decodedRecoveryKey
}

private fun decodeAliceSSSSRecoveryKey(): RawBytesKeySpec {
    val aliceRecoveryKey = "EsTd Ptqg Qakz Xz3R 4276 cT5w GDrW TYXU wBUd wjyj xWPm 92e9"

    return decodeSSSSRecoveryKey(aliceRecoveryKey)
}

private fun decodeSSSSRecoveryKey(recoveryKey: String): RawBytesKeySpec {
    // Note: Came across `BackupRecoveryKey.fromBase58(backupRecoveryKey)`
    //   via `org.matrix.rustcomponents.sdk.crypto.BackupRecoveryKey.Companion.fromBase58`
    //   or directly `import org.matrix.android.sdk.api.session.crypto.keysbackup.BackupRecoveryKey.Companion.fromBase58`.
    //   This can be a bit confusing, since the "Recovery Key" shown by clients is also encoded in base58, and this
    //   function would successfully decode `aliceRecoveryKey`. However, `aliceRecoveryKey` is the encoded private key
    //   for the SSSS store, which can then be used to decrypt the backup key.

    val ssssPrivateKeySpec = RawBytesKeySpec.fromRecoveryKey(recoveryKey)
    if (ssssPrivateKeySpec == null) {
        println("Decoded sssPrivateKeySpec is null!")
        exitProcess(1)
    }
    return ssssPrivateKeySpec
}