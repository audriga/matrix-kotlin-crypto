//import keybackup.SecretStorageKeyContent
import DemoUtils.Companion.createExampleEncryptedEvent
import org.audriga.matrix.crypto.moshi.MoshiProvider
import org.audriga.matrix.crypto.SharedSecretStorage.Companion.checkRecoveryKey
import org.audriga.matrix.crypto.keybackup.KeyBackupService.Companion.createKeyBackupVersionRequest
import org.audriga.matrix.crypto.keybackup.KeyBackupService.Companion.toJsonString
import org.audriga.matrix.crypto.ssss.CrossSigningUtils.Companion.uploadCrossSigningKeysRequestToJson
import org.audriga.matrix.crypto.ssss.SecretStorageKey.Companion.formatRecoveryKey
import org.audriga.matrix.crypto.ssss.SecretStorageKey.Companion.generateSecretStorageKey
import org.audriga.matrix.crypto.ssss.SecretStorageService.Companion.DEFAULT_KEY_ID
import org.audriga.matrix.crypto.ssss.SecretStorageService.Companion.KEY_ID_BASE
import org.audriga.matrix.crypto.ssss.SecretStorageService.Companion.createSecretStorageKeyVerificationInfo
import org.audriga.matrix.crypto.ssss.SecretStorageService.Companion.encryptKeyForAccountDataStorage
import org.matrix.android.sdk.api.crypto.SSSS_ALGORITHM_AES_HMAC_SHA2
import org.matrix.android.sdk.api.session.crypto.crosssigning.KEYBACKUP_SECRET_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.MASTER_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.SELF_SIGNING_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.USER_SIGNING_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.android.sdk.api.session.securestorage.SsssKeySpec
import org.matrix.rustcomponents.sdk.crypto.*
import uniffi.matrix_sdk_crypto.LocalTrust
import java.io.File
import java.util.*
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
    rustOlmMachine.outgoingRequests().forEach { println("Request: $it ${it.javaClass}") }
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
    val formattedRecoveryKey = recoveryKey.formatRecoveryKey()

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

    val createKeysBackupVersionBody = createKeyBackupVersionRequest(publicKey, rustOlmMachine)
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
    rustOlmMachine.getMissingSessions(users)
    rustOlmMachine.setLocalTrust(USER_ID, DEVICE_ID, LocalTrust.VERIFIED)
    val device = rustOlmMachine.getDevice(rustOlmMachine.userId(), rustOlmMachine.deviceId(), 30u)
    println("Device: $device\n...locally trusted: ${device?.locallyTrusted}")


    val encryptedEvent = createExampleEncryptedEvent(rustOlmMachine, roomId, users)
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



//private fun SecretStorageKeyContent.toJsonString(): String {
//    val moshi = MoshiProvider.providesMoshi()
//    return moshi
//        .adapter(SecretStorageKeyContent::class.java)
//        .toJson(this)
//}



// Copied function from DefaultSharedSecretStorageService.kt
internal fun storeSecret(
    name: String,
    secretBase64: String,
    keyId: String,
    ssssKeySpec: SsssKeySpec) {
    val uploadContent = encryptKeyForAccountDataStorage(ssssKeySpec, name, secretBase64, keyId)
    updateUserAccountData(
        type = name,
        uploadContent = uploadContent
    )
}

// Copied function from DefaultSharedSecretStorageService.kt (modified)
internal fun generateKey(
    keyId: String,
    key: SsssKeySpec?
): Triple<String, String, RawBytesKeySpec> {
    println("======= Creating key $keyId ============")
    val (ssssKeySpec, recoveryKey) = generateSecretStorageKey(key)
    val (iv, mac) = updateDefaultSecretStorageKey("$KEY_ID_BASE.$keyId", ssssKeySpec)
    println("Recovery Key: $recoveryKey")

    // Trying to verify the key would decrypt correctly
    val decodedSpec = RawBytesKeySpec.fromRecoveryKey(recoveryKey)!!
    val recoveryKeyCorrect = checkRecoveryKey(decodedSpec, SSSS_ALGORITHM_AES_HMAC_SHA2, iv, mac)
    if (recoveryKeyCorrect) {
        println("Verify recovery key works")
    } else{
        println("Verify recovery key does not work")
    }

    return Triple(keyId, recoveryKey, ssssKeySpec)
}

internal fun updateDefaultSecretStorageKey(type: String, ssssKeySpec: RawBytesKeySpec): Pair<String?, String?> {
    // For some reason I could not find evidence of the element app doing this?
    //  But according to my spec understanding this should be done.
    val (initializationVector, mac, uploadContent) = createSecretStorageKeyVerificationInfo(ssssKeySpec)

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


