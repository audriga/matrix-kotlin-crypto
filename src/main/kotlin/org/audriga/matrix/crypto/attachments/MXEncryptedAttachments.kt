package org.audriga.matrix.crypto.attachments
/*
 * Copyright 2020 The Matrix.org Foundation C.I.C.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import org.audriga.matrix.crypto.fromBase64NoPadding
import org.audriga.matrix.crypto.fromBase64Url
import org.audriga.matrix.crypto.toBase64NoPadding
import org.audriga.matrix.crypto.toBase64Url
import org.matrix.android.sdk.api.session.crypto.model.EncryptedFileInfo
import org.matrix.android.sdk.api.session.crypto.model.EncryptedFileKey
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.logging.Level
import java.util.logging.Logger
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.time.Clock

// Based on copy of from org.matrix.android.sdk.internal.crypto.attachments
object MXEncryptedAttachments {
    private val mLogger = Logger.getLogger(MXEncryptedAttachments::class.java.name)

    private const val CRYPTO_BUFFER_SIZE = 32 * 1024
    private const val CIPHER_ALGORITHM = "AES/CTR/NoPadding"
    private const val SECRET_KEY_SPEC_ALGORITHM = "AES"
    private const val MESSAGE_DIGEST_ALGORITHM = "SHA-256"

    @JvmStatic
    fun encrypt(
        clearStream: InputStream,
        outputFile: File,
        clock: Clock,
        progress: ((current: Int, total: Int) -> Unit)
    ): EncryptedFileInfo {
        val t0 = clock.now().toEpochMilliseconds()
        val (initVectorBytes, key) = generateIvAndKey()

        val messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM)

        outputFile.outputStream().use { outputStream ->
            val encryptCipher = Cipher.getInstance(CIPHER_ALGORITHM)
            val secretKeySpec = SecretKeySpec(key, SECRET_KEY_SPEC_ALGORITHM)
            val ivParameterSpec = IvParameterSpec(initVectorBytes)
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)

            val data = ByteArray(CRYPTO_BUFFER_SIZE)
            var read: Int
            var encodedBytes: ByteArray
            clearStream.use { inputStream ->
                val estimatedSize = inputStream.available()
                progress.invoke(0, estimatedSize)
                read = inputStream.read(data)
                var totalRead = read
                while (read != -1) {
                    progress.invoke(totalRead, estimatedSize)
                    encodedBytes = encryptCipher.update(data, 0, read)
                    messageDigest.update(encodedBytes, 0, encodedBytes.size)
                    outputStream.write(encodedBytes)
                    read = inputStream.read(data)
                    totalRead += read
                }
            }

            // encrypt the latest chunk
            encodedBytes = encryptCipher.doFinal()
            messageDigest.update(encodedBytes, 0, encodedBytes.size)
            outputStream.write(encodedBytes)
        }

        return EncryptedFileInfo(
            url = null,
            key = EncryptedFileKey(
                alg = "A256CTR",
                ext = true,
                keyOps = listOf("encrypt", "decrypt"),
                kty = "oct",
                k = key.toBase64Url(),
            ),
            iv = initVectorBytes.toBase64NoPadding(),
            hashes = mapOf("sha256" to messageDigest.digest().toBase64NoPadding()),
            v = "v2"
        )
            .also { mLogger.log(Level.INFO, "Encrypt in ${clock.now().toEpochMilliseconds() - t0}ms") }
    }


    /***
     * Encrypt an attachment stream.
     * DO NOT USE for big files, it will load all in memory
     * @param attachmentStream the attachment stream. Will be closed after this method call.
     * @param clock a clock to retrieve current time
     * @return the encryption file info
     */
    @JvmStatic
    fun encryptAttachment(attachmentStream: InputStream, clock: Clock): EncryptionResult {
        val t0 = clock.now().toEpochMilliseconds()
        val (initVectorBytes, key) = generateIvAndKey()

        val messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM)
        val byteArrayOutputStream = ByteArrayOutputStream()
        byteArrayOutputStream.use { outputStream ->
            val encryptCipher = Cipher.getInstance(CIPHER_ALGORITHM)
            val secretKeySpec = SecretKeySpec(key, SECRET_KEY_SPEC_ALGORITHM)
            val ivParameterSpec = IvParameterSpec(initVectorBytes)
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)

            val data = ByteArray(CRYPTO_BUFFER_SIZE)
            var read: Int
            var encodedBytes: ByteArray

            attachmentStream.use { inputStream ->
                read = inputStream.read(data)
                while (read != -1) {
                    encodedBytes = encryptCipher.update(data, 0, read)
                    messageDigest.update(encodedBytes, 0, encodedBytes.size)
                    outputStream.write(encodedBytes)
                    read = inputStream.read(data)
                }
            }

            // encrypt the latest chunk
            encodedBytes = encryptCipher.doFinal()
            messageDigest.update(encodedBytes, 0, encodedBytes.size)
            outputStream.write(encodedBytes)
        }

        return EncryptionResult(
            encryptedFileInfo = EncryptedFileInfo(
                url = null,
                key = EncryptedFileKey(
                    alg = "A256CTR",
                    ext = true,
                    keyOps = listOf("encrypt", "decrypt"),
                    kty = "oct",
                    k = key.toBase64Url(),
                ),
                iv = initVectorBytes.toBase64NoPadding(),
                hashes = mapOf("sha256" to messageDigest.digest().toBase64NoPadding()),
                v = "v2"
            ),
            encryptedByteArray = byteArrayOutputStream.toByteArray()
        )
            .also { mLogger.log(Level.INFO, "Encrypt in ${clock.now().toEpochMilliseconds() - t0}ms") }
    }

    private fun generateIvAndKey(): Pair<ByteArray, ByteArray> {
        val secureRandom = SecureRandom()

        // generate a random iv key
        // Half of the IV is random, the lower order bits are zeroed
        // such that the counter never wraps.
        // See https://github.com/matrix-org/matrix-ios-kit/blob/3dc0d8e46b4deb6669ed44f72ad79be56471354c/MatrixKit/Models/Room/MXEncryptedAttachments.m#L75
        val initVectorBytes = ByteArray(16) { 0.toByte() }

        val ivRandomPart = ByteArray(8)
        secureRandom.nextBytes(ivRandomPart)

        System.arraycopy(ivRandomPart, 0, initVectorBytes, 0, ivRandomPart.size)

        val key = ByteArray(32)
        secureRandom.nextBytes(key)
        return Pair(initVectorBytes, key)
    }

    /**
     * Decrypt an attachment.
     *
     * @param attachmentStream the attachment stream. Will be closed after this method call.
     * @param elementToDecrypt the elementToDecrypt info
     * @param outputStream the outputStream where the decrypted attachment will be write.
     * @param clock a clock to retrieve current time
     * @return true in case of success, false in case of error
     */
    @JvmStatic
    public fun decryptAttachment(
        attachmentStream: InputStream?,
        elementToDecrypt: ElementToDecrypt?,
        outputStream: OutputStream,
        clock: Clock
    ): Boolean {
        // sanity checks
        if (null == attachmentStream || elementToDecrypt == null) {
            mLogger.log(Level.WARNING, "## decryptAttachment() : null stream")
            return false
        }

        val t0 = clock.now().toEpochMilliseconds()

        try {
            val key = elementToDecrypt.k.fromBase64Url()
            val initVectorBytes = elementToDecrypt.iv.fromBase64NoPadding()

            val decryptCipher = Cipher.getInstance(CIPHER_ALGORITHM)
            val secretKeySpec = SecretKeySpec(key, SECRET_KEY_SPEC_ALGORITHM)
            val ivParameterSpec = IvParameterSpec(initVectorBytes)
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)

            val messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM)

            var read: Int
            val data = ByteArray(CRYPTO_BUFFER_SIZE)
            var decodedBytes: ByteArray

            attachmentStream.use { inputStream ->
                read = inputStream.read(data)
                while (read != -1) {
                    messageDigest.update(data, 0, read)
                    decodedBytes = decryptCipher.update(data, 0, read)
                    outputStream.write(decodedBytes)
                    read = inputStream.read(data)
                }
            }

            // decrypt the last chunk
            decodedBytes = decryptCipher.doFinal()
            outputStream.write(decodedBytes)

            val currentDigestValue = messageDigest.digest().toBase64NoPadding()

            if (elementToDecrypt.sha256 != currentDigestValue) {
                mLogger.log(Level.WARNING, "## decryptAttachment() :  Digest value mismatch")
                return false
            }

            mLogger.log(Level.INFO, "Decrypt in ${clock.now().toEpochMilliseconds() - t0} ms")
            return true
        } catch (oom: OutOfMemoryError) {
            mLogger.log(Level.WARNING, "## decryptAttachment() failed: OOM", oom)
        } catch (e: Exception) {
            mLogger.log(Level.WARNING, "## decryptAttachment() failed", e)
        }

        return false
    }
}
