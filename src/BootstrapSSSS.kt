//import keybackup.SecretStorageKeyContent
import keybackup.*
import org.matrix.android.sdk.api.crypto.SSSS_ALGORITHM_AES_HMAC_SHA2
import org.matrix.android.sdk.api.session.crypto.crosssigning.*
import org.matrix.android.sdk.api.session.crypto.keysbackup.MegolmBackupAuthData
import org.matrix.android.sdk.api.session.crypto.keysbackup.computeRecoveryKey
import org.matrix.android.sdk.api.session.securestorage.EncryptedSecretContent
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.android.sdk.api.session.securestorage.SsssKeySpec
import org.matrix.android.sdk.api.util.JsonDict
import org.matrix.rustcomponents.sdk.crypto.*
import uniffi.matrix_sdk_crypto.LocalTrust
import java.io.File
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and
import kotlin.io.encoding.Base64
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine

private const val OLM_MACHINE_PATH = "/tmp/olmMachine"
private const val USER_ID_LOCAL_PART = "freshuser19"
private const val HOMESERVER = "ZetaHorologii"

private const val USER_ID = "@$USER_ID_LOCAL_PART:$HOMESERVER"
private const val DEVICE_ID = "MIGRDEVICE"
//private const val ROOM_PLACEHOLDER_LOCAL_PART = "Placeholder"
//private const val ROOM_PLACEHOLDER_ID = "!$ROOM_PLACEHOLDER_LOCAL_PART:$HOMESERVER"

private const val BASE_URL = "http://$HOMESERVER:8008/"
private const val URI_API_PREFIX_PATH = "_matrix/client"
private const val URI_API_PREFIX_PATH_V3 = "$URI_API_PREFIX_PATH/v3/"
private const val USER_DEVICE_QUERY_PARAMETERS = "?user_id=$USER_ID&device_id=$DEVICE_ID"
private const val CURL_HEADERS = $$" --header \"Authorization: Bearer $TOKEN_AS\" \\\n" +
        " --header 'Content-Type: application/json'"
private const val KEY_ID_BASE = "m.secret_storage.key"
private const val DEFAULT_KEY_ID = "m.secret_storage.default_key"
private const val SCRIPT_PATH = "/tmp/"
private val scriptFile1 = File(SCRIPT_PATH+"setupSSSS.sh")
private val scriptFile2 = File(SCRIPT_PATH+"postEncryptedMsg.sh")
fun main() {
    deleteDirectoryByPath(OLM_MACHINE_PATH)
    if (scriptFile1.exists()) {
        scriptFile1.delete()
    }
    scriptFile1.createNewFile()
    if (scriptFile2.exists()) {
        scriptFile2.delete()
    }
    scriptFile2.createNewFile()
    val rustOlmMachine = RustOmlMachine(USER_ID, DEVICE_ID, OLM_MACHINE_PATH, null)

    bootstrapEncryption(rustOlmMachine)
}

private fun bootstrapEncryption(rustOlmMachine: RustOmlMachine) {
    scriptFile1.writeText(
        $$"""#!/usr/bin/env bash
        |
        |echo "Create the new user"
        |podman exec -it docker_synapse_1 register_new_matrix_user http://localhost:8008 -c /data/homeserver.yaml  -u $$USER_ID_LOCAL_PART -p test
        | echo "Get other devices"
        | OTHER_DEVICES=$(curl --request GET \
        | --url "$$BASE_URL$${URI_API_PREFIX_PATH_V3}devices?user_id=$$USER_ID" \
        | --header "Authorization: Bearer $TOKEN_AS" | jq  "[.devices[].device_id]"); echo $OTHER_DEVICES
        |echo "Delete other devices"
        |curl --request POST \
        |  --url "$$BASE_URL$${URI_API_PREFIX_PATH_V3}delete_devices/?user_id=$$USER_ID" \
        |  --header "Authorization: Bearer $TOKEN_AS" \
        |  -d '{
        |    "devices": '"$OTHER_DEVICES"'
        |  }'
        |echo "Create the migration device"
        |curl --request PUT \
        | --url "$$BASE_URL$${URI_API_PREFIX_PATH_V3}devices/$$DEVICE_ID?user_id=$$USER_ID" \
        | --header "Authorization: Bearer $TOKEN_AS" \
        | -d '{
        |    "display_name": "Migration Worker"
        |  }'
        |
    """.trimMargin())


    val bootstrapCrossSigningResult = rustOlmMachine.bootstrapCrossSigning()
    crossSigningUploadRequests(bootstrapCrossSigningResult)
    // Todo maybe I need to mark the three key requests as sent? rustOlmMachine.markRequestAsSent(bootstrapCrossSigningResult.uploadKeysRequest.requestId)
    println(rustOlmMachine.crossSigningStatus())
    val exportCrossSigningKeys = rustOlmMachine.exportCrossSigningKeys()!!
    println(exportCrossSigningKeys)
//    val wrappedBackupRecoveryKey = org.matrix.android.sdk.api.session.crypto.keysbackup.BackupRecoveryKey()
    val backupRecoveryKey = BackupRecoveryKey()
    createKeyBackupVersion(backupRecoveryKey, rustOlmMachine)

    val recoveryKey = create4S(exportCrossSigningKeys, backupRecoveryKey)

    prettyPrintRecoveryKey(recoveryKey)

    // TODO need to know roomId before encrypting messages for said room
    createNewRoom()
    println("Ececute script and enter room id")
    val roomId = readln()
    createMegolmSessionAndEncryptMessage(rustOlmMachine, roomId)
}

private fun prettyPrintRecoveryKey(recoveryKey: String) {
    val formattedRecoveryKey = recoveryKey.split("(?<=\\G....)".toRegex()).joinToString(" ")

    println("Recovery Key: $formattedRecoveryKey")
    scriptFile1.appendText("\necho; echo \"Recovery Key: $formattedRecoveryKey\"\n")
    scriptFile1.setExecutable(true)
    scriptFile2.setExecutable(true)
}

// See also https://github.com/element-hq/element-android/blob/bda600be58542a9265124e5dea03a6182446e44d/matrix-sdk-android/src/androidTest/java/org/matrix/android/sdk/common/CryptoTestHelper.kt#L317
// and https://github.com/element-hq/element-android/blob/bda600be58542a9265124e5dea03a6182446e44d/vector/src/main/java/im/vector/app/features/crypto/recover/BootstrapCrossSigningTask.kt#L189C1-L194C14
private fun create4S(
    exportCrossSigningKeys: CrossSigningKeyExport,
    backupRecoveryKey: BackupRecoveryKey
): String {
    // Create 4S key
//    val emptyKeySigner = EmptyKeySigner()// todo why does the element code use empty signer??
    val (keyId, recoveryKey, keySpec) = generateKey(
        UUID.randomUUID().toString(),
        null // params.keySpec,
    )
    // Set default key
    updateUserAccountData(DEFAULT_KEY_ID, mapOf("key" to keyId))
    // Encrypt SSSS keys (and upload them)
    storeSecret(MASTER_KEY_SSSS_NAME, exportCrossSigningKeys.masterKey!!, keyId, keySpec)
    storeSecret(SELF_SIGNING_KEY_SSSS_NAME, exportCrossSigningKeys.selfSigningKey!!, keyId, keySpec)
    storeSecret(USER_SIGNING_KEY_SSSS_NAME, exportCrossSigningKeys.userSigningKey!!, keyId, keySpec)
    storeSecret(KEYBACKUP_SECRET_SSSS_NAME, backupRecoveryKey.toBase64(), keyId, keySpec)

    return recoveryKey
}

private fun createKeyBackupVersion(
    backupRecoveryKey: BackupRecoveryKey,
    rustOlmMachine: RustOmlMachine
) {
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
//    val keyBackupVersion = KeysVersionResult(
//        algorithm = createKeysBackupVersionBody.algorithm,
//        authData = createKeysBackupVersionBody.authData,
//        version = "1",
//        // We can assume that the server does not have keys yet
//        count = 0,
//        hash = ""
//    )

    val createKeysBackupVersionBody = CreateKeysBackupVersionBody(
        algorithm = publicKey.backupAlgorithm,
        authData = signedMegolmBackupAuthData.toJsonDict()
    )

    val keyBackupVersionBodyJson = createKeysBackupVersionBody.toJsonString()
    //     @POST(NetworkConstants.URI_API_PREFIX_PATH_UNSTABLE + "room_keys/version")
    //    suspend fun createKeysBackupVersion(@Body createKeysBackupVersionBody: CreateKeysBackupVersionBody): KeysVersion
    /**
     * Todo: Print a curl call. Example below
     * curl --request POST \
     *  --url "http://ZetaHorologii:8008/_matrix/client/v3/room_keys/version?user_id=@freshuser3:ZetaHorologii&device_id=migDevice" \
     *  --header "Authorization: Bearer $TOKEN" -d '{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"Lu1i9JEM7LIuRrTw1OtwXnsmae6S8VP19Slgo2dj0Go","signatures":{"@freshuser3:ZetaHorologii":{"ed25519:migDevice":"UY6lhazVelusJpWEokBHCST5+Oir2txGmeFCjfq1LWGtm56/XILJVUf0f2hHn5aEG1Du6MD7j4g99XBtIukgCQ","ed25519:IUeCwKVdoKplkxX1JcCQ+5dojEFmqz4m9Q55wva/OY0":"soNuBYAXo9MlkIO7zHjA99SLbNcq/mkLcUTfgeVgCuAEbDYyAm5qSO+ucpbvBTOqbfgVw1zwuo2ciJmb9eAPAw"}}}}
     * '
     */
    println("Create Keys Backup version body:\n$createKeysBackupVersionBody")
    val createKeysBackupVersionPath = "room_keys/version"
    val curlCall = "# Curl 4: Create keys backup version\n" +
            "curl --request POST \\\n" +
            " --url \"$BASE_URL$URI_API_PREFIX_PATH_V3$createKeysBackupVersionPath$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
            "$CURL_HEADERS \\\n" +
            " -d '$keyBackupVersionBodyJson'"
    scriptFile1.appendText(curlCall+"\n")
    println(curlCall)

    // TODO: Now upload the private keys, see note from thursday


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

//    val retrievedMegolmBackupAuthData = keyBackupVersion.getAuthDataAsMegolmBackupAuthData()
    rustOlmMachine.enableBackupV1(publicKey, "1")
}

private fun createMegolmSessionAndEncryptMessage(rustOlmMachine: RustOmlMachine, roomId: String) {
    val users = listOf("@alice:$HOMESERVER", "@bob:$HOMESERVER", "foo")
    val settings = EncryptionSettings(
        algorithm = EventEncryptionAlgorithm.MEGOLM_V1_AES_SHA2,
        onlyAllowTrustedDevices = true,
        rotationPeriod = 604800000.toULong(),
        rotationPeriodMsgs = 100.toULong(),
        historyVisibility = HistoryVisibility.SHARED,
        errorOnVerifiedUserProblem = false,
    )
    rustOlmMachine.getMissingSessions(users)
    rustOlmMachine.setLocalTrust(USER_ID, DEVICE_ID, LocalTrust.VERIFIED)
    val device = rustOlmMachine.getDevice(rustOlmMachine.userId(), rustOlmMachine.deviceId(), 30u)
    println("Device: $device\n...locally trusted: ${device?.locallyTrusted}")


    val shareRoomKeyRequests = rustOlmMachine.shareRoomKey(roomId, users, settings)
    // todo this is empty, no matter what I supply as users
    println(shareRoomKeyRequests)


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
//    rustOlmMachine.sign(encryptedEvent)
    println("Encrypted Event:\n$encryptedEvent")
    uploadEncryptedEvent(roomId,encryptedEvent)
//    rustOlmMachine.verifyIdentity() TODO for other user's identities. Probably need to first import that users megolm session/ public x-signing master key? but how?
//    rustOlmMachine.importDecryptedRoomKeys()
//    val verifyDeviceRequest = rustOlmMachine.verifyDevice(USER_ID, DEVICE_ID).body
//    println("VerifyDevice Request:\n$verifyDeviceRequest")// TODO
//    uploadSignatures(verifyDeviceRequest)

//    rustOlmMachine.verifyBackup() already done after create keys backup version

    // todo Why is "is_verified":false?
    val backupRoomKeys = rustOlmMachine.backupRoomKeys()
    println(backupRoomKeys)
    backupRoomKeysRequest(backupRoomKeys)
}

private fun uploadEncryptedEvent(roomId: String, encryptedEvent: String) {
    val sendEncryptedPath = """rooms/"'$roomId'"/send/m.room.encrypted/$(uuidgen)"""
    val curlCall = "# Upload encrypted event\n" +
            "curl --request PUT \\\n" +
            " --url \"$BASE_URL$URI_API_PREFIX_PATH_V3$sendEncryptedPath$USER_DEVICE_QUERY_PARAMETERS&version=1\" \\\n" +
            "$CURL_HEADERS \\\n" +
            " -d '$encryptedEvent'"
    scriptFile2.appendText(curlCall + "\n")
    println(curlCall)
}

private fun backupRoomKeysRequest(backupRoomKeys: Request?) {
    val keyBackupRequestRooms = (backupRoomKeys as Request.KeysBackup).rooms //.replace(ROOM_PLACEHOLDER_ID, $$"'\"$NEW_ROOM\"'")
    val verifiedKeyBackupRequestRooms = keyBackupRequestRooms.replace(""""is_verified":false""", """"is_verified":true""")
    val keyBackupRequestPayload = """{"rooms": $verifiedKeyBackupRequestRooms}"""
    val backupRoomKeysPath = "room_keys/keys"
    val curlCall = "# Upload room key backup\n" +
            "curl --request PUT \\\n" +
            " --url \"$BASE_URL$URI_API_PREFIX_PATH_V3$backupRoomKeysPath$USER_DEVICE_QUERY_PARAMETERS&version=1\" \\\n" +
            "$CURL_HEADERS \\\n" +
            " -d '$keyBackupRequestPayload'"
    scriptFile2.appendText(curlCall + "\n")
    println(curlCall)
}

private fun createNewRoom() {
    val createRoomCurlCall = """
        # Create new room
        curl --request POST \
        --url "$BASE_URL${URI_API_PREFIX_PATH_V3}createRoom$USER_DEVICE_QUERY_PARAMETERS" \
        $CURL_HEADERS \
        -d '{
        "preset": "trusted_private_chat",
        "invite": [],
        "is_direct": false,
        "initial_state": [{
          "content":{
            "algorithm": "m.megolm.v1.aes-sha2",
            "rotation_period_ms": 604800000,
            "rotation_period_msgs": 100
          },
          "type": "m.room.encryption"
        }]
        }'
        """
    println(createRoomCurlCall)
    scriptFile1.appendText(createRoomCurlCall + "\n")
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
    val curlCall = "# Curl 1: Upload public keys\n" +
            "curl --request POST \\\n" +
            " --url \"$BASE_URL$URI_API_PREFIX_PATH_V3$keyUploadPath$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
            "$CURL_HEADERS \\\n" +
            " -d '${uploadKeysRequest.body}'"
    scriptFile1.appendText(curlCall+"\n")
    println(curlCall)

}

private fun uploadSigningKeys(uploadSigningKeysRequest: UploadSigningKeysRequest) {

    val uploadSigningKeysBodyJson = uploadCrossSigningKeysRequestToJson(uploadSigningKeysRequest)
    // @POST(NetworkConstants.URI_API_PREFIX_PATH_UNSTABLE + "keys/device_signing/upload")
    println("uploadSigningKeys: $uploadSigningKeysRequest")
    val deviceSigningPath = "keys/device_signing/upload"
    val curlCall = "# Curl 2: Upload public signing keys\n" +
            "curl --request POST \\\n" +
            " --url \"$BASE_URL$URI_API_PREFIX_PATH_V3$deviceSigningPath$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
            "$CURL_HEADERS \\\n" +
            " -d '$uploadSigningKeysBodyJson'"
    scriptFile1.appendText(curlCall+"\n")
    println(curlCall)
}

private fun uploadSignatures(uploadSignatureRequest: SignatureUploadRequest) {
    // @POST(NetworkConstants.URI_API_PREFIX_PATH_UNSTABLE + "keys/signatures/upload")
    val signaturesBody = uploadSignatureRequest.body
    println("uploadSignature: $uploadSignatureRequest")
    uploadSignatures(signaturesBody)
}

private fun uploadSignatures(signaturesBody: String) {
    val uploadSignaturesPath = "keys/signatures/upload"
    val curlCall = "# Curl 3: Upload key signature\n" +
            "curl --request POST \\\n" +
            " --url \"$BASE_URL$URI_API_PREFIX_PATH_V3$uploadSignaturesPath$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
            "$CURL_HEADERS \\\n" +
            " -d '$signaturesBody'"
    scriptFile1.appendText(curlCall + "\n")
    println(curlCall)
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

//private fun SecretStorageKeyContent.toJsonString(): String {
//    val moshi = MoshiProvider.providesMoshi()
//    return moshi
//        .adapter(SecretStorageKeyContent::class.java)
//        .toJson(this)
//}

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

// Copied function from DefaultSharedSecretStorageService.kt
internal fun storeSecret(
    name: String,
    secretBase64: String,
    keyId: String,
    ssssKeySpec: SsssKeySpec) {
    val encryptedContents = HashMap<String, EncryptedSecretContent>()
    encryptAesHmacSha2(ssssKeySpec, name, secretBase64).let {
                        encryptedContents[keyId] = it
                    }
    updateUserAccountData(
        type = name,
        uploadContent = mapOf("encrypted" to encryptedContents)
    )
}

// Copied function from DefaultSharedSecretStorageService.kt (modified)
internal fun generateKey(
    keyId: String,
    key: SsssKeySpec?
): Triple<String, String, RawBytesKeySpec> {
    println("======= Creating key $keyId ============")
        val bytes = (key as? RawBytesKeySpec)?.privateKey
            ?: ByteArray(32).also {
                SecureRandom().nextBytes(it)
            }

    val ssssKeySpec = RawBytesKeySpec(bytes)
    val (iv, mac) = updateDefaultSecretStorageKey("$KEY_ID_BASE.$keyId", ssssKeySpec)
    val recoveryKey = computeRecoveryKey(bytes)
    println("Recovery Key: $recoveryKey")

    // Trying to verify the key would decrypt correctly
    val decodedSpec = RawBytesKeySpec.fromRecoveryKey(recoveryKey)!!
    val empty = ByteArray(32) { 0.toByte() }.toString(Charsets.UTF_8) // initialized to zero
    val (_, mac1, _, _) = encryptAesHmacSha2(
        decodedSpec,
        "",
        empty,
        IvParameterSpec( Base64.withPadding(Base64.PaddingOption.ABSENT).decode(iv!!))
    )
    if (mac.equals(mac1)) {
        println("Verify recovery key works")
    } else{
        println("Verify recovery key does not work")
    }

    return Triple(keyId, recoveryKey, ssssKeySpec)
}

internal fun updateDefaultSecretStorageKey(type: String, ssssKeySpec: RawBytesKeySpec): Pair<String?, String?> {
    // For some reason I could not find evidence of the element app doing this?
    //  But according to my spec understanding this should be done.
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


    updateUserAccountData(type, uploadContent)

    return Pair(initializationVector, mac)
}

private fun updateUserAccountData(type: String, uploadContent: Map<String, Any>) {
//    /**
//     * Set some account_data for the user.
//     *
//     * @param userId the user id
//     * @param type the type
//     * @param params the put params
//     */
//    @PUT(NetworkConstants.URI_API_PREFIX_PATH_R0 + "user/{userId}/account_data/{type}")
//    suspend fun setAccountData(
//        @Path("userId") userId: String,
//        @Path("type") type: String,
//        @Body params: Any
//    )
    val moshi = MoshiProvider.providesMoshi()
    val uploadContentJson = moshi.adapter(Map::class.java).toJson(uploadContent)
    val userPath = "user/$USER_ID/"
    val accountDataPath = "account_data/"
    val curlCall = "# Curl: Upload user account data \n" +
            "curl --request PUT \\\n" +
            " --url \"$BASE_URL$URI_API_PREFIX_PATH_V3$userPath$accountDataPath$type$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
            "$CURL_HEADERS \\\n" +
            " -d '$uploadContentJson'"
    scriptFile1.appendText(curlCall+"\n")
    println(curlCall)
}

//Copied from DefaultSharedSecretStorageService
@Throws
private fun encryptAesHmacSha2(
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
