import keybackup.CreateKeysBackupVersionBody
import keybackup.CryptoInfoMapper
import keybackup.JsonCanonicalizer
import keybackup.MoshiProvider
import keybackup.RestKeyInfo
import keybackup.SignalableMegolmBackupAuthData
import keybackup.UploadSigningKeysBody
import org.matrix.android.sdk.api.session.crypto.crosssigning.CryptoCrossSigningKey
import org.matrix.android.sdk.api.session.crypto.keysbackup.MegolmBackupAuthData
import org.matrix.android.sdk.api.util.JsonDict
import org.matrix.rustcomponents.sdk.crypto.BackupRecoveryKey
import org.matrix.rustcomponents.sdk.crypto.BootstrapCrossSigningResult
import org.matrix.rustcomponents.sdk.crypto.EncryptionSettings
import org.matrix.rustcomponents.sdk.crypto.EventEncryptionAlgorithm
import org.matrix.rustcomponents.sdk.crypto.HistoryVisibility
import org.matrix.rustcomponents.sdk.crypto.Request
import org.matrix.rustcomponents.sdk.crypto.SignatureUploadRequest
import org.matrix.rustcomponents.sdk.crypto.UploadSigningKeysRequest
import uniffi.matrix_sdk_crypto.LocalTrust
import kotlin.jvm.java
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine

private const val olmMachinePath = "/tmp/olmMachine"
private const val userId = "@freshuser3:ZetaHorologii"
private const val deviceId = "migDevice"

private const val baseUrl = "http://ZetaHorologii:8008/"
private const val URI_API_PREFIX_PATH = "_matrix/client"
private const val URI_API_PREFIX_PATH_V3 = "$URI_API_PREFIX_PATH/v3/"
private const val USER_DEVICE_QUERY_PARAMETERS = "?user_id=$userId&device_id=$deviceId"
private const val CURL_HEADERS = $$" --header \"Authorization: Bearer $TOKEN_AS\" \\\n" +
        " --header 'Content-Type: application/json'"

fun main() {
    deleteDirectoryByPath(olmMachinePath)
    val rustOlmMachine = RustOmlMachine(userId, deviceId, olmMachinePath, null)

    bootstrapEncryption(rustOlmMachine)
}

private fun bootstrapEncryption(rustOlmMachine: RustOmlMachine) {
    val bootstrapCrossSigningResult = rustOlmMachine.bootstrapCrossSigning()
    crossSigningUploadRequests(bootstrapCrossSigningResult)
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
    println("Canonicalized Backup Auth Data:\n$canonicalJson\n-")

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
//
//        println(signedMegolmBackupAuthData.toJsonDict().toString())

    val createKeysBackupVersionBody = CreateKeysBackupVersionBody(
        algorithm = publicKey.backupAlgorithm,
        authData = signedMegolmBackupAuthData.toJsonDict()
    )

    val keyBackupVersionBodyJson = createKeysBackupVersionBody.toJsonString()
    //     @POST(NetworkConstants.URI_API_PREFIX_PATH_UNSTABLE + "room_keys/version")
    //    suspend fun createKeysBackupVersion(@Body createKeysBackupVersionBody: CreateKeysBackupVersionBody): KeysVersion
    println("Create Keys Backup version body:\n$keyBackupVersionBodyJson\n-")

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
    val users = listOf("@alice:ZetaHorologii", "@bob:ZetaHorologii", "foo")
    val settings = EncryptionSettings(
        algorithm = EventEncryptionAlgorithm.MEGOLM_V1_AES_SHA2,
        onlyAllowTrustedDevices = true,
        rotationPeriod = 604800000.toULong(),
        rotationPeriodMsgs = 100.toULong(),
        historyVisibility = HistoryVisibility.SHARED,
        errorOnVerifiedUserProblem = false,
    )
    rustOlmMachine.getMissingSessions(users)
    rustOlmMachine.setLocalTrust(userId, deviceId, LocalTrust.VERIFIED)
    val device = rustOlmMachine.getDevice(rustOlmMachine.userId(), rustOlmMachine.deviceId(), 30u)
    println("Device: $device\n...locally trusted: ${device?.locallyTrusted}")
    val shareRoomKeyRequests = rustOlmMachine.shareRoomKey(roomId, users, settings)


    println(shareRoomKeyRequests)

    val backupRoomKeys = rustOlmMachine.backupRoomKeys()
    println(backupRoomKeys)

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
    println("Encrypted Event:\n$encryptedEvent")
}

private fun crossSigningUploadRequests(bootstrapCrossSigningResult: BootstrapCrossSigningResult) {
    uploadKeys(bootstrapCrossSigningResult.uploadKeysRequest as Request.KeysUpload)


    uploadSigningKeys(bootstrapCrossSigningResult.uploadSigningKeysRequest)

    uploadSignatures(bootstrapCrossSigningResult.uploadSignatureRequest)
}

private fun uploadKeys(uploadKeysRequest: Request.KeysUpload) {
    // @POST(NetworkConstants.URI_API_PREFIX_PATH_R0 + "keys/upload")
    println("uploadKeys: $uploadKeysRequest")
    val keyUploadPath = "keys/upload"
    println(
        "Curl 1:\n" +
                "curl --request POST \\\n" +
                " --url \"$baseUrl$URI_API_PREFIX_PATH_V3$keyUploadPath$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
                "$CURL_HEADERS \\\n" +
                " -d '${uploadKeysRequest.body}'"
    )

}

private fun uploadSigningKeys(uploadSigningKeysRequest: UploadSigningKeysRequest) {

    val uploadSigningKeysBodyJson = uploadCrossSigningKeysRequestToJson(uploadSigningKeysRequest)
    // @POST(NetworkConstants.URI_API_PREFIX_PATH_UNSTABLE + "keys/device_signing/upload")
    println("uploadSigningKeys: $uploadSigningKeysRequest")
    val deviceSigningPath = "keys/device_signing/upload"
    println(
        "Curl 2:\n" +
                "curl --request POST \\\n" +
                " --url \"$baseUrl$URI_API_PREFIX_PATH_V3$deviceSigningPath$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
                "$CURL_HEADERS \\\n" +
                " -d '$uploadSigningKeysBodyJson'"
    )
}

private fun uploadSignatures(uploadSignatureRequest: SignatureUploadRequest) {
    // @POST(NetworkConstants.URI_API_PREFIX_PATH_UNSTABLE + "keys/signatures/upload")
    println("uploadSignature: $uploadSignatureRequest")
    val uploadSignaturesPath = "keys/signatures/upload"
    println(
        "Curl 3:\n" +
                "curl --request POST \\\n" +
                " --url \"$baseUrl$URI_API_PREFIX_PATH_V3$uploadSignaturesPath$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
                "$CURL_HEADERS \\\n" +
                " -d '${uploadSignatureRequest.body}'"
    )
}


private fun uploadCrossSigningKeysRequestToJson(uploadSigningKeysRequest: UploadSigningKeysRequest): String? {
//        UploadSigningKeysBody(
//            masterKey = params.masterKey.toRest(),
//            userSigningKey = params.userKey.toRest(),
//            selfSigningKey = params.selfSignedKey.toRest(),
//            auth = params.userAuthParam?.asMap()
//        )
    val moshi = MoshiProvider.providesMoshi()
    val restKeyInfoAdapter = moshi.adapter(RestKeyInfo::class.java)
    // todo: This appears to convert from RestKeyInfo to CryptoModel and back to RestKeyInfo, can probably be simplified?
    val masterKey = restKeyInfoAdapter.fromJson(uploadSigningKeysRequest.masterKey)!!.toCryptoModel().toRest()
    val selfSigningKey = restKeyInfoAdapter.fromJson(uploadSigningKeysRequest.selfSigningKey)!!.toCryptoModel().toRest()
    val userSigningKey = restKeyInfoAdapter.fromJson(uploadSigningKeysRequest.userSigningKey)!!.toCryptoModel().toRest()
    val uploadSigningKeysBody = UploadSigningKeysBody(
        masterKey = masterKey,
        userSigningKey = userSigningKey,
        selfSigningKey = selfSigningKey
    )
    val uploadSigningKeysBodyJson = moshi.adapter(UploadSigningKeysBody::class.java).toJson(uploadSigningKeysBody)
    return uploadSigningKeysBodyJson
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

internal fun CryptoCrossSigningKey.toRest(): RestKeyInfo {
    return CryptoInfoMapper.map(this)
}
