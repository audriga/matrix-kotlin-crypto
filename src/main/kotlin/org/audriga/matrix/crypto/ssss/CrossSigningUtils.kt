package org.audriga.matrix.crypto.ssss

import keybackup.MoshiProvider
import org.audriga.matrix.crypto.keybackup.CryptoInfoMapper
import org.audriga.matrix.crypto.keybackup.RestKeyInfo
import org.audriga.matrix.crypto.keybackup.UploadSigningKeysBody
import org.matrix.android.sdk.api.session.crypto.crosssigning.CryptoCrossSigningKey
import org.matrix.rustcomponents.sdk.crypto.UploadSigningKeysRequest

class CrossSigningUtils {
    companion object {
        internal fun CryptoCrossSigningKey.toRest(): RestKeyInfo {
            return CryptoInfoMapper.map(this)
        }

        @JvmStatic
        fun uploadCrossSigningKeysRequestToJson(uploadSigningKeysRequest: UploadSigningKeysRequest): String? {
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
    }
}