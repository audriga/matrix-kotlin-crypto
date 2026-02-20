@file:Suppress("SameParameterValue")

import org.matrix.android.sdk.api.crypto.MXCRYPTO_ALGORITHM_MEGOLM_BACKUP
import org.matrix.android.sdk.api.session.crypto.crosssigning.KEYBACKUP_SECRET_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.MASTER_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.SELF_SIGNING_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.USER_SIGNING_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.keysbackup.KeysBackupService
import org.matrix.android.sdk.api.session.crypto.keysbackup.MegolmBackupAuthData
import org.matrix.android.sdk.api.session.crypto.keysbackup.MegolmBackupCreationInfo
// Todo: We currently solely use a few parsing methods and data classes.
//  Potentially copy paste them in the codebase (like we did for some internal utils we needed)
//  And remove dependency to matrix-android-sdk2 (only using rustcomponents sdk directly).
import org.matrix.rustcomponents.sdk.crypto.BackupRecoveryKey
// Note: Corresponding matrix-android-sdk2 import: org.matrix.android.sdk.api.session.crypto.keysbackup.BackupRecoveryKey
import org.matrix.android.sdk.api.session.securestorage.EncryptedSecretContent
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.rustcomponents.sdk.crypto.CrossSigningKeyExport
import org.matrix.rustcomponents.sdk.crypto.EncryptionSettings
import org.matrix.rustcomponents.sdk.crypto.EventEncryptionAlgorithm
import org.matrix.rustcomponents.sdk.crypto.HistoryVisibility
import org.matrix.rustcomponents.sdk.crypto.MegolmV1BackupKey
import org.matrix.rustcomponents.sdk.crypto.version
import uniffi.matrix_sdk_crypto.DecryptionSettings
import uniffi.matrix_sdk_crypto.TrustRequirement
import java.io.File
import kotlin.system.exitProcess
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine
import org.matrix.rustcomponents.sdk.crypto.ProgressListener as RustProgressListener

const val aliceRecoveryKey = "EsTd Ptqg Qakz Xz3R 4276 cT5w GDrW TYXU wBUd wjyj xWPm 92e9"
const val eventFromBob = $$"""{
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

const val eventAliceSelf = $$"""{
      "type": "m.room.encrypted",
      "sender": "@alice:ZetaHorologii",
      "content": {
        "algorithm": "m.megolm.v1.aes-sha2",
        "ciphertext": "AwgAEpAB+QO9QMAXFDmTinvKNAUUQDm28/VHQnB2ZKGEqOr7CQyahnI9LARKodHeUVUumvRKm1FLtl/48XztIcLlMZ/Few3i/vt1X9aC0NPRTLCFhIStjqQuogFMX0LZA5p7MHam547jggrhNO3d1uPqZI8cZsvA6zB34SEgL3YZ7T++e8FKGAM3BnZPRo4h1aXqT8lyWv9rlR9xNuIPFAkmsut82dyELg/6Jq4yNaKofQCZPLLxIEXzTIzHIt8YscGwqJX3uBPdAL+qrAMZkDgQ/ohxy8H1FXzEWz8G",
        "device_id": "KEEMLNBZMM",
        "sender_key": "WhT7AqHcWAqvZovcJ0ycwB2SGI12Ds51CuAD8Cf7/xs",
        "session_id": "O7Vzimw4VRcMPBoDnYMr4ViP1PPzsVYz2yRf+ZDcYY0"
      },
      "room_id": "!HQmlfpAoAHVOFZEvCg:ZetaHorologii",
      "origin_server_ts": 1771574979718,
      "unsigned": {
        "age": 536982
      },
      "event_id": "$ZtWJDIDAMkrYIsPUICUpyAM712j0bVVuOXZQgX0xh30",
      "user_id": "@alice:ZetaHorologii",
      "age": 536982
    }"""

const val eventCreatedByKotlin = $$"""{
  "type": "m.room.encrypted",
  "sender": "@alice:ZetaHorologii",
  "content": {
    "algorithm": "m.megolm.v1.aes-sha2",
    "ciphertext": "AwgAEpABdUdyn5Jf7h6IGESaEBmDz2P5FeQWpO+mGHa+05wJVBdrnpta/t1XAU50e6KH7/iaUL9tV0TfGV5tAkNualCvnHB4aZtiyz074VHh+p9MCTjKdn8PqeMvpBI+IZHaDh5azqQrZFLh3IgrmIdBMpaQ2euY6YOWTt7NhNutWAdp/P6Q/P0WiHOD9CefKIaD4emzbk5P5jfXdoCvlR+/TYLC92u1lEYC3Wkql6TXO0XYcNUZhyiEyNPLMBCiugsUU5+dkUjN49kjlNFS5qNjhFHXK0zVhowTu+4M",
    "device_id": "migDevice",
    "sender_key": "B1A48ltUYtWG7eTfMPCIYTjBBKpdecdBOdELEJZf0gE",
    "session_id": "U2i4vsmWg9QN5PivI+o4hLSxZmdzUFCE8cYOQX7D8fI"
  },
  "origin_server_ts": 1771575996965,
  "unsigned": {
    "membership": "join",
    "age": 126
  },
  "event_id": "$XLNU4RWxDB7VQGhUWnTeXDmRZh7VgdnSlVHpZ0Zi28o",
  "room_id": "!HQmlfpAoAHVOFZEvCg:ZetaHorologii"
}
"""

const val eventAliceNewer = $$"""
    {
      "type": "m.room.encrypted",
      "sender": "@alice:ZetaHorologii",
      "content": {
        "algorithm": "m.megolm.v1.aes-sha2",
        "ciphertext": "AwgFEpAB302kfo1hhWIH6qWSSJzcmSBjZlV0JwwEUitml49v74Lhe1WspN6xLuDpt8at8WqMI3fVY83TmB4InGnzPT/ZuoQaIiD1nMC2XFgN2AZr+kpz2Bj+C66MIFlFXLLFt2BGNRuzeBDGvZfGWBvBMfJ4SnJIjKJMPdlSpxwCMrEW9EHYslg3HjpQuzIqLwHrZEdwmT2kZIH8PKFtwnn/SWzXY6iDSgOOGeqpov8tu/Tkwpfs98EYvbffW0UKMo21uGEt3dvNtYAdtQD+1vQcWByYyGdzFsoYaFwL",
        "device_id": "KEEMLNBZMM",
        "sender_key": "WhT7AqHcWAqvZovcJ0ycwB2SGI12Ds51CuAD8Cf7/xs",
        "session_id": "O7Vzimw4VRcMPBoDnYMr4ViP1PPzsVYz2yRf+ZDcYY0"
      },
      "room_id": "!HQmlfpAoAHVOFZEvCg:ZetaHorologii",
      "origin_server_ts": 1771578627371,
      "unsigned": {
        "age": 6948
      },
      "event_id": "$G54nOci748ObusSoSU8dgaqKKjbWhOipWgPDcZKc8x4",
      "user_id": "@alice:ZetaHorologii",
      "age": 6948
    }

"""
//    val roomId = "!CkmkaydvMtvVXXukVn:ZetaHorologii" // Room ABC
const val roomId = "!HQmlfpAoAHVOFZEvCg:ZetaHorologii" // Room Alice Self
//    val sessionId = "06pJO2EEEkWxans9viRZllaagZQO/XV4K2/Iuz0RMTQ" // Bob megolm session in room ABC
const val sessionId = "O7Vzimw4VRcMPBoDnYMr4ViP1PPzsVYz2yRf+ZDcYY0" // Alice megolm session in room Alice Self

fun main() {
    val version = version()
    // Note, could also get additional version info via Matrix.getCryptoVersion(longFormat = true)
    println("Rust SDK version, $version!")

    val olmMachinePath = "/tmp/olmMachine"
    deleteDirectoryByPath(olmMachinePath)
    val rustOlmMachine = RustOmlMachine("@alice:ZetaHorologii", "migDevice", olmMachinePath, null)

//    bootstrapEncryption(rustOlmMachine)

    // rustOlmMachine after the Decrypt-PoC contains the imported decrypted megolm session.
    val (ssssPrivateKeySpec, decodedRecoveryKey) = decryptPoC(
        rustOlmMachine,
        aliceRecoveryKey,
        roomId,
        sessionId,
        eventAliceNewer
    )
    val backupPublicKey = decodedRecoveryKey.megolmV1PublicKey()



    encryptWithMegolmSession(rustOlmMachine, backupPublicKey, roomId)
//    verifyDeviceWithDecryptedCrossSigningKeys(ssssPrivateKeySpec, rustOlmMachine)
    deleteDirectoryByPath(olmMachinePath)
}

private fun bootstrapEncryption(rustOlmMachine: RustOmlMachine) {
    rustOlmMachine.bootstrapCrossSigning()
    println(rustOlmMachine.crossSigningStatus())
    val exportCrossSigningKeys = rustOlmMachine.exportCrossSigningKeys()
    println(exportCrossSigningKeys)
    val backupRecoveryKey = BackupRecoveryKey()
    val publicKey = backupRecoveryKey.megolmV1PublicKey()
    println("PublicKey: $publicKey")
//    rustOlmMachine.sign()

//    val backupAuthData = SignalableMegolmBackupAuthData(
//        publicKey = publicKey.publicKey,
//        privateKeySalt = publicKey.passphraseInfo?.privateKeySalt,
//        privateKeyIterations = publicKey.passphraseInfo?.privateKeyIterations
//    )
//    val canonicalJson = JsonCanonicalizer.getCanonicalJson(
//        Map::class.java,
//        backupAuthData.signalableJSONDictionary()
//    )
//
//    val signedMegolmBackupAuthData = MegolmBackupAuthData(
//        publicKey = backupAuthData.publicKey,
//        privateKeySalt = backupAuthData.privateKeySalt,
//        privateKeyIterations = backupAuthData.privateKeyIterations,
//        signatures = rustOlmMachine.sign(canonicalJson)
//    )
//
//    MegolmBackupCreationInfo(
//        algorithm = publicKey.backupAlgorithm,
//        authData = signedMegolmBackupAuthData,
//        recoveryKey = backupRecoveryKey
//    )

    val publicKeySignature: Map<String, Map<String, String>> = rustOlmMachine.sign(
        """{
        "public_key": $publicKey
    }""".trimMargin()
    )
    val publicKeySignatureJson = publicKeySignature.map { (key, value) ->
        "\"$key\": {\n${
            value.map { (keyInner, valueInner) -> "\"$keyInner\":\"$valueInner\"" }.joinToString(",\n")
        }\n}"
    }.joinToString(",\n")
    println(publicKeySignatureJson)

    val backupInfoJson = """{
        "algorithm": "$MXCRYPTO_ALGORITHM_MEGOLM_BACKUP",
        "auth_data": {
            "public_key": "${publicKey.publicKey}",
            "signatures": {
                $publicKeySignatureJson
            }
        }
    }""".trimMargin()
    println(backupInfoJson)
    val verifyBackup = rustOlmMachine.verifyBackup(backupInfoJson)
    println(verifyBackup)
    // TODO Have not figured out yet, how to properly create the key backup with a signature.
}

private fun verifyDeviceWithDecryptedCrossSigningKeys(
    ssssPrivateKeySpec: RawBytesKeySpec,
    rustOlmMachine: RustOmlMachine
) {
    val crossSigningKeyExport = decryptCrossSigningKeys(ssssPrivateKeySpec)
    println(crossSigningKeyExport)

    // TODO: For some reason this appears to not do anything. Is this a bug in the SDK?
    // Reference: Here element imports the cross signing keys
    // - https://github.com/element-hq/element-android/blob/bda600be58542a9265124e5dea03a6182446e44d/vector/src/main/java/im/vector/app/features/crypto/verification/self/SelfVerificationViewModel.kt#L472
    // What if in the following linked code, verify is never calles, because getIdentity(userId()) always returns null? https://github.com/element-hq/element-android/blob/bda600be58542a9265124e5dea03a6182446e44d/matrix-sdk-android/src/main/java/org/matrix/android/sdk/internal/crypto/OlmMachine.kt#L864
    rustOlmMachine.importCrossSigningKeys(crossSigningKeyExport)

    val userId = rustOlmMachine.userId()
    println("UserID: $userId")
    // TODO: This returns null/ can't find the identity in the olm machine...
    val identity = rustOlmMachine.getIdentity(userId, 30u)

    println("Identity: $identity")
    println(rustOlmMachine.crossSigningStatus())
    println(rustOlmMachine.exportCrossSigningKeys())

    rustOlmMachine.verifyIdentity(rustOlmMachine.userId()) // Why does this return Unknown user identity?
    val verifyDeviceRequest = rustOlmMachine.verifyDevice("@alice:ZetaHorologii", "migDevice")
    println(verifyDeviceRequest)
}

private fun decryptCrossSigningKeys(ssssPrivateKeySpec: RawBytesKeySpec): CrossSigningKeyExport {
    val crossSigningMasterEncrypted = EncryptedSecretContent(
        initializationVector = "AgUhdm/B70VZv4bvSlbd2A==",
        ciphertext = "+3xlEQcZS/aQlVeTR71PxIegmIaETttn5nJUKFcYZVl623RUxy0FH+GmdQ==",
        mac = "znjAMl9de6q0Fl9KuVjzJjDD9HTvp52G3F5boUkm4aQ="
    )
    val decryptedB64CrossSigningMasterKey = decryptAesHmacSha2(
        ssssPrivateKeySpec,
        MASTER_KEY_SSSS_NAME,
        crossSigningMasterEncrypted,
    )
    println(decryptedB64CrossSigningMasterKey)

    val userSigningKeyEncrypted = EncryptedSecretContent(
        initializationVector = "03bMr5kI+0Asdt87Rd8JJw==",
        ciphertext = "k3ffkBCPoCf/FzD0e4ImDc1n8mjHQMs9K04z1gog3h+B8ERYg2KcQngSKg==",
        mac = "Cx/t8wLH+YvBGVOuvRNTWNoiJkuKHuhqJVF2E0ZMOGo=",
    )
    val decryptedB64UserSigningKey = decryptAesHmacSha2(
        ssssPrivateKeySpec,
        USER_SIGNING_KEY_SSSS_NAME,
        userSigningKeyEncrypted,
    )
    println(decryptedB64UserSigningKey)

    val selfSigningKeyEncrypted = EncryptedSecretContent(
        initializationVector = "BJuqBJiLMvQXSX+PaaQRQg==",
        ciphertext = "D8KVKLTzH4p8Qhkmu6W49OF+LGKczKFhCF71FeUpG4oMZ5nq46g+dCq+SA==",
        mac = "mWOE4TdDcwVNUHQ0oOhT7Eqk4Lev3HuC2RoyUYiRIT4=",

        )
    val decryptedB64SelfSigningKey = decryptAesHmacSha2(
        ssssPrivateKeySpec,
        SELF_SIGNING_KEY_SSSS_NAME,
        selfSigningKeyEncrypted,
    )
    println(decryptedB64SelfSigningKey)

    val crossSigningKeyExport = CrossSigningKeyExport(
        masterKey = decryptedB64CrossSigningMasterKey,
        selfSigningKey = decryptedB64SelfSigningKey,
        userSigningKey = decryptedB64UserSigningKey
    )
    return crossSigningKeyExport
}

private fun encryptWithMegolmSession(
    rustOlmMachine: RustOmlMachine,
    backupPublicKey1: MegolmV1BackupKey,
    roomId: String
) {
    val users = listOf("@alice:ZetaHorologii", "@bob:ZetaHorologii", "foo")
    val missingSessions = rustOlmMachine.getMissingSessions(users)
    println(missingSessions)
    // todo: Not sure why missingSessions always returns null, and shareRoomKey always returns [],
    //  no matter which list of users I supply
    // Via PrepareToEncryptUseCase.kt / CryptoRoomInfo.kt
    val settings = EncryptionSettings(
        algorithm = EventEncryptionAlgorithm.MEGOLM_V1_AES_SHA2,
        onlyAllowTrustedDevices = true,
        rotationPeriod = 604800000.toULong(),
        rotationPeriodMsgs = 100.toULong(),
        historyVisibility = HistoryVisibility.SHARED,
        errorOnVerifiedUserProblem = false,
    )
    val shareRoomKeyRequests = rustOlmMachine.shareRoomKey(roomId, users, settings)

    println(shareRoomKeyRequests)
    // Returns error "Session wasn't created nor shared", if shareRoomKey was not previously called.
//    rustOlmMachine.receiveSyncChanges()
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
    rustOlmMachine.enableBackupV1(backupPublicKey1, "1")
    val backupRoomKeys = rustOlmMachine.backupRoomKeys()
    println(backupRoomKeys)
}

private fun decryptPoC(
    rustOlmMachine: RustOmlMachine,
    recoveryKey: String,
    roomId: String,
    sessionId: String,
    event: String,
    ): Pair<RawBytesKeySpec, BackupRecoveryKey> {
    val ssssPrivateKeySpec = decodeSSSSRecoveryKey(recoveryKey)

    val decodedRecoveryKey = decryptAliceMegolmBackupKey(ssssPrivateKeySpec)
    val decryptedMegolmSession = decryptSampleMegolmSession(decodedRecoveryKey)

    createOlmMachineAndImportDecryptedSession(
        decryptedMegolmSession,
        roomId,
        sessionId,
        rustOlmMachine,
    )

    decryptRoomEvent(rustOlmMachine, roomId, event)
    return Pair(ssssPrivateKeySpec, decodedRecoveryKey)
}

private fun decryptRoomEvent(rustOmlMachine: RustOmlMachine, roomId: String, event: String) {
    // Decrypting a message event that is encrypted with the session we just imported
    val decryptedEvent = rustOmlMachine.decryptRoomEvent(
        event = event,
        roomId = roomId,
        handleVerificationEvents = false,
        strictShields = false,
        decryptionSettings = DecryptionSettings(TrustRequirement.UNTRUSTED)
    )
    println(decryptedEvent.clearEvent)

//    //  I can decrypt the same event twice, which means the olmMachine is keeping track of previous states
//    val (clearEvent2, _, _, _, _) = rustOmlMachine.decryptRoomEvent(
//        event = event,
//        roomId = roomId,
//        handleVerificationEvents = false,
//        strictShields = false,
//        decryptionSettings = DecryptionSettings(TrustRequirement.UNTRUSTED)
//    )
//    println(clearEvent2)
}

private fun createOlmMachineAndImportDecryptedSession(
    decryptedMegolmSession: String,
    roomId: String,
    sessionId: String,
    rustOlmMachine: RustOmlMachine,
) {

    // importDecryptedRoomKeys Expects the serialized form of MegolmSessionData from internal class
    // package org.matrix.android.sdk.internal.crypto
    // This should be the same as the decrypted session, with additional keys for sessionId and roomId,
    // see decryptKeyBackupData in RustKeyBackupService.kt of matrix-android-sdk2 .
    // Todo: This appears to be loosing info like first_message_index or forwarded_count. Does the olmMachine not need
    //  this? Do we need to check ourselves if we can decrypt a given message with a given session?
    val encodedKey = "[" + decryptedMegolmSession.dropLast(1) +
            ",\"room_id\":\"$roomId\"" +
            ",\"session_id\":\"$sessionId\"" +
            "}]"
    val rustListener = object : RustProgressListener {
        override fun onProgress(progress: Int, total: Int) {
            println("Rust is processing keys $progress | $total")
        }
    }
    rustOlmMachine.importDecryptedRoomKeys(encodedKey, rustListener)
    println("Is the previous call async?")
//    sleep(1000)
}

private fun decryptSampleMegolmSession(decodedRecoveryKey: BackupRecoveryKey): String {
    // Some megolm session gotten via room_keys/keys api call
    /*
    {
  "rooms": {
    "!CkmkaydvMtvVXXukVn:ZetaHorologii": { // Room ABC
      "sessions": {
        "06pJO2EEEkWxans9viRZllaagZQO/XV4K2/Iuz0RMTQ": { // Session from Bob
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
//    val decryptedMegolmSession = decodedRecoveryKey.decryptV1(
//        ephemeralKey = "8TRPnq4uaEZ8PQr6pklIfbxtjeogxY0bcraMjmACsns",
//        mac = "rdYvArAPNec",
//        ciphertext = "achSSv18s4DHbUS5+NxlNrcyDjzZk6mFlDmrOPOeRhulRkAcAQUGNNRhgacO5okYxG6uOmH3rWuVUOwXB1JLknaMN9O4jBNrgmHkQjekujT7SQaYFJhIf/YQQy5EVxOeI0S9vpPdhVVf/ekl5X6XZhL727P98Uscf2o4094UHdlA2g6upYU/FNRejzZ3TA88UWNOJM7v8Sg4cttOMchUJLgOp6vAl2tcbMDykTDO4iSIpJX3ai5LVhIjLs4Ygr2VFp41zgWBOU8CW7hFSZPg1UBHCw7yy3IuwxOKs3zTOkblU2T2y3ovOLyuoYisDX9Zi7l2mvQsq9uNSxzt6YMYDT4h6azuJTNnZ/RxBznUaTgap0n+C0Vqt8C/gkeKz44lLRq8HiG8bKoI6b2ViwbiE+tN0G30nHdY0dykZUh/rE2x98z3iotP02OvQoY0ixXzRpEif/ONbHBO7Cbq3X1GGH57dFHJc6eIRLplnUzzHuJ8HSit5caRLcr6UqLSIFQMZE5s22N1Ve1t9FKs7FGHeRsLEl90TJEo0uL5tUExUDQQLVFrIsH2GTy521zdCxn9MXE30cKgAhOJwRifLra2eqme1jlARNmB8pkmpTzRV7KhrGLcNd4xa/L2UUWQtB2rCM8YCs41JXMQZQ5XbhRCFA"
//    )
    val decryptedMegolmSession = decodedRecoveryKey.decryptV1(
        ephemeralKey = "vlu39YCgEk8UwkfnkQ5eolJmC1KlY2HD7EK/yqbBM0U",
        mac = "E3YSPwOWzbg",
        ciphertext = "zmOBVT1qSnMchjOerYHG8YAPa7tEGna4PQ+scmFoleolTRMPEQ/D7bdyJVJ0LGtPGV3j6P1TdUvCttAKGQxisn02ZiorNbOjeqfcyNqHlZuoAYL2DI54bkzEfN+Ebg0GkS6vZyXvbKeQxT0B/Ob6Zozep1zUqfeiMO9eAs1SjJbrIXtGA1O4c0hIym9WSYf55PC/ASLq2TTcnWp9hLiFnRlOZqztiEaI6vhIh1tGfO0yLleggdRX+aaSUlilADp9IGhXYQQV9Q0e/kZcKGl6eQQs7Zc3GJ678IZdIVSyRMLVITsF10wdPOZJ2h/bekKilq2xOOXwPpQh9n0EUKMjSCkXGRN5V27a8+//eXMseAfpNXW96SAJSiwwlz+d3t9A6AX7ye2QYDcdDwNVFIaqdrOQVlbONIVZMpeYJfeeDkWDIun1WLGUtbEWERE7LWwk29d4dTNsrm8jTStA98DAzk8UsMqkcv45jdDwHfeNXOeTTqQR4PrIxgS/Wu31Ox8e0dhCS7Cn1aIdxPExqIkuazVwxWwNHUlrBNx/cbl7AtkRYEyuEgegmtx23FIBABhDXlQ1Gxd6jEeLkV+hXuNI2twCATerF2b9lUhM+METOm25s5pGsW4e5qfVqIDAClkRPHA8xgYL7H8tb48ICazrOg"
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

fun deleteDirectoryByPath(path: String) {
    deleteDirectory(File(path))
}
fun deleteDirectory(directory: File) {
    if (directory.exists() && directory.isDirectory) {
        directory.listFiles()?.forEach { file ->
            if (file.isDirectory) {
                deleteDirectory(file)
            } else {
                file.delete()
            }
        }
        directory.delete()
    }
}