import keybackup.CreateKeysBackupVersionBody
import keybackup.CryptoInfoMapper
import keybackup.JsonCanonicalizer
import keybackup.MoshiProvider
import keybackup.RestKeyInfo
import keybackup.SecretStorageKeyContent
import keybackup.SignalableMegolmBackupAuthData
import keybackup.SsssKeyCreationInfo
import keybackup.UploadSigningKeysBody
import org.matrix.android.sdk.api.crypto.SSSS_ALGORITHM_AES_HMAC_SHA2
import org.matrix.android.sdk.api.session.crypto.crosssigning.CryptoCrossSigningKey
import org.matrix.android.sdk.api.session.crypto.crosssigning.KEYBACKUP_SECRET_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.MASTER_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.SELF_SIGNING_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.crosssigning.USER_SIGNING_KEY_SSSS_NAME
import org.matrix.android.sdk.api.session.crypto.keysbackup.MegolmBackupAuthData
import org.matrix.android.sdk.api.session.crypto.keysbackup.computeRecoveryKey
import org.matrix.android.sdk.api.session.securestorage.EmptyKeySigner
import org.matrix.android.sdk.api.session.securestorage.EncryptedSecretContent
import org.matrix.android.sdk.api.session.securestorage.KeySigner
import org.matrix.android.sdk.api.session.securestorage.RawBytesKeySpec
import org.matrix.android.sdk.api.session.securestorage.SsssKeySpec
import org.matrix.android.sdk.api.util.JsonDict
import org.matrix.rustcomponents.sdk.crypto.BackupRecoveryKey
import org.matrix.rustcomponents.sdk.crypto.BootstrapCrossSigningResult
import org.matrix.rustcomponents.sdk.crypto.CrossSigningKeyExport
import org.matrix.rustcomponents.sdk.crypto.EncryptionSettings
import org.matrix.rustcomponents.sdk.crypto.EventEncryptionAlgorithm
import org.matrix.rustcomponents.sdk.crypto.HistoryVisibility
import org.matrix.rustcomponents.sdk.crypto.Request
import org.matrix.rustcomponents.sdk.crypto.SignatureUploadRequest
import org.matrix.rustcomponents.sdk.crypto.UploadSigningKeysRequest
import uniffi.matrix_sdk_crypto.LocalTrust
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and
import kotlin.jvm.java
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine

private const val olmMachinePath = "/tmp/olmMachine"
private const val userId = "@freshuser4:ZetaHorologii"
private const val deviceId = "migDevice"

private const val baseUrl = "http://ZetaHorologii:8008/"
private const val URI_API_PREFIX_PATH = "_matrix/client"
private const val URI_API_PREFIX_PATH_V3 = "$URI_API_PREFIX_PATH/v3/"
private const val USER_DEVICE_QUERY_PARAMETERS = "?user_id=$userId&device_id=$deviceId"
private const val CURL_HEADERS = $$" --header \"Authorization: Bearer $TOKEN_AS\" \\\n" +
        " --header 'Content-Type: application/json'"
const val KEY_ID_BASE = "m.secret_storage.key"
private const val DEFAULT_KEY_ID = "m.secret_storage.default_key"
fun main() {
    deleteDirectoryByPath(olmMachinePath)
    val rustOlmMachine = RustOmlMachine(userId, deviceId, olmMachinePath, null)

    bootstrapEncryption(rustOlmMachine)
}

private fun bootstrapEncryption(rustOlmMachine: RustOmlMachine) {
    val bootstrapCrossSigningResult = rustOlmMachine.bootstrapCrossSigning()
    crossSigningUploadRequests(bootstrapCrossSigningResult)
    // Todo maybe I need to mark the three key requests as sent? rustOlmMachine.markRequestAsSent(bootstrapCrossSigningResult.uploadKeysRequest.requestId)
    println(rustOlmMachine.crossSigningStatus())
    val exportCrossSigningKeys = rustOlmMachine.exportCrossSigningKeys()!!
    println(exportCrossSigningKeys)
//    val wrappedBackupRecoveryKey = org.matrix.android.sdk.api.session.crypto.keysbackup.BackupRecoveryKey()
    val backupRecoveryKey = BackupRecoveryKey()
    createKeyBackupVersion(backupRecoveryKey, rustOlmMachine)

    create4S(exportCrossSigningKeys, backupRecoveryKey)

    createMegolmSessionAndEncryptMessage(rustOlmMachine)
}

// See also https://github.com/element-hq/element-android/blob/bda600be58542a9265124e5dea03a6182446e44d/matrix-sdk-android/src/androidTest/java/org/matrix/android/sdk/common/CryptoTestHelper.kt#L317
// and https://github.com/element-hq/element-android/blob/bda600be58542a9265124e5dea03a6182446e44d/vector/src/main/java/im/vector/app/features/crypto/recover/BootstrapCrossSigningTask.kt#L189C1-L194C14
private fun create4S(
    exportCrossSigningKeys: CrossSigningKeyExport,
    backupRecoveryKey: BackupRecoveryKey
) {
    // Create 4S key
    val emptyKeySigner = EmptyKeySigner()// todo why does the element code use empty signer??
//    object : KeySigner {
//        override fun sign(canonicalJson: String): Map<String, Map<String, String>>? {
//            TODO("Not yet implemented")
//        }
//    }
    val (keyId, content, recoveryKey, keySpec) = generateKey(
        UUID.randomUUID().toString(),
        null, // params.keySpec,
        "ssss_key",
        emptyKeySigner
    )
    // Set default key
    updateUserAccountData(DEFAULT_KEY_ID, mapOf("key" to keyId))
    // Encrypt SSSS keys (and upload them)
    storeSecret(MASTER_KEY_SSSS_NAME, exportCrossSigningKeys.masterKey!!, keyId, keySpec)
    storeSecret(SELF_SIGNING_KEY_SSSS_NAME, exportCrossSigningKeys.selfSigningKey!!, keyId, keySpec)
    storeSecret(USER_SIGNING_KEY_SSSS_NAME, exportCrossSigningKeys.userSigningKey!!, keyId, keySpec)
    storeSecret(KEYBACKUP_SECRET_SSSS_NAME, backupRecoveryKey.toBase64(), keyId, keySpec)

    println("Recovery Key: $recoveryKey")// todo: Element sais this key is not correct. Probably iv/ mac in the default key are set in a wrong way
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
    println(
        "Curl 4: Create keys backup version\n" +
                "curl --request POST \\\n" +
                " --url \"$baseUrl$URI_API_PREFIX_PATH_V3$createKeysBackupVersionPath$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
                "$CURL_HEADERS \\\n" +
                " -d '$keyBackupVersionBodyJson'"
    )

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

private fun createMegolmSessionAndEncryptMessage(rustOlmMachine: RustOmlMachine) {
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

    // todo Why is "is_verified":false?
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
        "Curl 1: Upload public keys\n" +
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
        "Curl 2: Upload public signing keys\n" +
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
        "Curl 3: Upload key signature\n" +
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

private fun SecretStorageKeyContent.toJsonString(): String {
    val moshi = MoshiProvider.providesMoshi()
    return moshi
        .adapter(SecretStorageKeyContent::class.java)
        .toJson(this)
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
    key: SsssKeySpec?,
    keyName: String,
    keySigner: KeySigner?
): SsssKeyCreationInfo {
        val bytes = (key as? RawBytesKeySpec)?.privateKey
            ?: ByteArray(32).also {
                SecureRandom().nextBytes(it)
            }

        val storageKeyContent = SecretStorageKeyContent(
            name = keyName,
            algorithm = SSSS_ALGORITHM_AES_HMAC_SHA2,
            passphrase = null
        )

    val canonicalStorageKeyJson = storageKeyContent.canonicalSignable()
//    val canonicalJson = JsonCanonicalizer.getCanonicalJson(
//        Map::class.java,
//        storageKeyContent.signalableJSONDictionary()
//    )

    val signedContent = keySigner?.sign(canonicalStorageKeyJson)?.let {
            storageKeyContent.copy(
                signatures = it
            )
        } ?: storageKeyContent
    val ssssKeySpec = RawBytesKeySpec(bytes)
    updateDefaultSecretStorageKey("$KEY_ID_BASE.$keyId", signedContent, ssssKeySpec)
    return  SsssKeyCreationInfo(
            keyId = keyId,
            content = storageKeyContent,
            recoveryKey = computeRecoveryKey(bytes),
            keySpec = ssssKeySpec
        )

}

internal fun updateDefaultSecretStorageKey(type: String, content: SecretStorageKeyContent, ssssKeySpec: RawBytesKeySpec) {
    // TODO For some reason I could not find evidence of the element app doing this?
    //  But according to my spec understanding this should be done.
    val (ciphertext, mac, ephemeral, initializationVector) = encryptAesHmacSha2(
        ssssKeySpec,
        type,
        content.toJsonString()
    )
    val uploadContent = mapOf(
        "algorithm" to "${content.algorithm}",
        "iv" to "$initializationVector",
        "mac" to "$mac"
    )


    updateUserAccountData(type, uploadContent)


    // todo Test the key would verify!

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
    val userPath = "user/$userId/"
    val accountDataPath = "account_data/"
    println(
        "Curl: Upload user account data \n" +
                "curl --request PUT \\\n" +
                " --url \"$baseUrl$URI_API_PREFIX_PATH_V3$userPath$accountDataPath$type$USER_DEVICE_QUERY_PARAMETERS\" \\\n" +
                "$CURL_HEADERS \\\n" +
                " -d '$uploadContentJson'"
    )
}

//Copied from DefaultSharedSecretStorageService
@Throws
private fun encryptAesHmacSha2(secretKey: SsssKeySpec, secretName: String, clearDataBase64: String): EncryptedSecretContent {
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

    val secureRandom = SecureRandom()
    val iv = ByteArray(16)
    secureRandom.nextBytes(iv)

    // clear bit 63 of the salt to stop us hitting the 64-bit counter boundary
    // (which would mean we wouldn't be able to decrypt on Android). The loss
    // of a single bit of salt is a price we have to pay.
    iv[9] = iv[9] and 0x7f

    val cipher = Cipher.getInstance("AES/CTR/NoPadding")

    val secretKeySpec = SecretKeySpec(aesKey, "AES")
    val ivParameterSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)
    // secret are not that big, just do Final
    val cipherBytes = cipher.doFinal(clearDataBase64.toByteArray())
    require(cipherBytes.isNotEmpty())

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
