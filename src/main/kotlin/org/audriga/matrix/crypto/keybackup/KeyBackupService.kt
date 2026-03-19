package org.audriga.matrix.crypto.keybackup

import keybackup.MoshiProvider
import org.matrix.android.sdk.api.session.crypto.keysbackup.MegolmBackupAuthData
import org.matrix.android.sdk.api.util.JsonDict
import org.matrix.rustcomponents.sdk.crypto.MegolmV1BackupKey
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine

class KeyBackupService {
    companion object {
        internal fun CreateKeysBackupVersionBody.toJsonString(): String {
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

        @JvmStatic
        fun createKeyBackupVersionRequestJson(
            publicKey: MegolmV1BackupKey,
            rustOlmMachine: RustOmlMachine
        ): String {
            val createKeysBackupVersionBody = createKeyBackupVersionRequest(publicKey, rustOlmMachine)
            val keyBackupVersionBodyJson = createKeysBackupVersionBody.toJsonString()
            return keyBackupVersionBodyJson
        }

        internal fun createKeyBackupVersionRequest(
            publicKey: MegolmV1BackupKey,
            rustOlmMachine: RustOmlMachine
        ): CreateKeysBackupVersionBody {
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
            return createKeysBackupVersionBody
        }
    }

}