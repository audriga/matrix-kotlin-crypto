import keybackup.CreateKeysBackupVersionBody
import keybackup.JsonCanonicalizer
import keybackup.MoshiProvider
import keybackup.SignalableMegolmBackupAuthData
import org.matrix.android.sdk.api.session.crypto.keysbackup.MegolmBackupAuthData
import org.matrix.android.sdk.api.util.JsonDict
import org.matrix.rustcomponents.sdk.crypto.BackupRecoveryKey
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine

fun main() {
    val olmMachinePath = "/tmp/olmMachine"
    deleteDirectoryByPath(olmMachinePath)
    val rustOlmMachine = RustOmlMachine("@freshuser1:ZetaHorologii", "migDevice", olmMachinePath, null)

    bootstrapEncryption(rustOlmMachine)
    }

    private fun bootstrapEncryption(rustOlmMachine: RustOmlMachine) {
        rustOlmMachine.bootstrapCrossSigning()
        println(rustOlmMachine.crossSigningStatus())
        val exportCrossSigningKeys = rustOlmMachine.exportCrossSigningKeys()
        println(exportCrossSigningKeys)
//    val wrappedBackupRecoveryKey = org.matrix.android.sdk.api.session.crypto.keysbackup.BackupRecoveryKey()
        val backupRecoveryKey = BackupRecoveryKey()
        val publicKey = backupRecoveryKey.megolmV1PublicKey()
        println("PublicKey: $publicKey")
//    rustOlmMachine.sign()

        val backupAuthData = SignalableMegolmBackupAuthData(
            publicKey = publicKey.publicKey,
            privateKeySalt = publicKey.passphraseInfo?.privateKeySalt,
            privateKeyIterations = publicKey.passphraseInfo?.privateKeyIterations
        )
        val canonicalJson = JsonCanonicalizer.getCanonicalJson(
            Map::class.java,
            backupAuthData.signalableJSONDictionary()
        )

        val signedMegolmBackupAuthData = MegolmBackupAuthData(
            publicKey = backupAuthData.publicKey,
            privateKeySalt = backupAuthData.privateKeySalt,
            privateKeyIterations = backupAuthData.privateKeyIterations,
            signatures = rustOlmMachine.sign(canonicalJson)
        )


//    MegolmBackupCreationInfo(
//        algorithm = publicKey.backupAlgorithm,
//        authData = signedMegolmBackupAuthData,
//        recoveryKey = backupRecoveryKey
//    )

        val createKeysBackupVersionBody = CreateKeysBackupVersionBody(
            algorithm = publicKey.backupAlgorithm,
            authData = signedMegolmBackupAuthData.toJsonDict()
        )

        val keyBackupVersionBodyJson = createKeysBackupVersionBody.toJsonString()
        println(keyBackupVersionBodyJson)

//    val publicKeySignature: Map<String, Map<String, String>> = rustOlmMachine.sign(
//        """{
//        "public_key": $publicKey
//    }""".trimMargin()
//    )
//    val publicKeySignatureJson = publicKeySignature.map { (key, value) ->
//        "\"$key\": {\n${
//            value.map { (keyInner, valueInner) -> "\"$keyInner\":\"$valueInner\"" }.joinToString(",\n")
//        }\n}"
//    }.joinToString(",\n")
//    println(publicKeySignatureJson)
//
//    val backupInfoJson = """{
//        "algorithm": "$MXCRYPTO_ALGORITHM_MEGOLM_BACKUP",
//        "auth_data": {
//            "public_key": "${publicKey.publicKey}",
//            "signatures": {
//                $publicKeySignatureJson
//            }
//        }
//    }""".trimMargin()
//    println(backupInfoJson)

        val verifyBackup = rustOlmMachine.verifyBackup(keyBackupVersionBodyJson)
        println("Verify works? $verifyBackup")
        // TODO Have not figured out yet, how to properly create the key backup with a signature.

//
//    val keyBackupVersion = KeysVersionResult(
//        algorithm = createKeysBackupVersionBody.algorithm,
//        authData = createKeysBackupVersionBody.authData,
//        version = "1",
//        // We can assume that the server does not have keys yet
//        count = 0,
//        hash = ""
//    )
//    val retrievedMegolmBackupAuthData = keyBackupVersion.getAuthDataAsMegolmBackupAuthData()
        rustOlmMachine.enableBackupV1(publicKey, "1")
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
        val backupRoomKeys = rustOlmMachine.backupRoomKeys()
        println(backupRoomKeys)
    }

    private fun CreateKeysBackupVersionBody.toJsonString(): String {
        val moshi = MoshiProvider.providesMoshi()
//    val adapter = moshi.adapter(Map::class.java)

        return moshi
            .adapter(CreateKeysBackupVersionBody::class.java)
            .toJson(this)
//        .let {
//            @Suppress("UNCHECKED_CAST")
//            adapter.fromJson(it) as JsonDict
//        }

    }

    // Copied internal function from MegolmBackupAuthData
    private fun MegolmBackupAuthData.toJsonDict(): JsonDict {
        val moshi = MoshiProvider.providesMoshi()
        val adapter = moshi.adapter(Map::class.java)

        return moshi
            .adapter(MegolmBackupAuthData::class.java)
            .toJson(this)
            .let {
                @Suppress("UNCHECKED_CAST")
                adapter.fromJson(it) as JsonDict
            }
    }
