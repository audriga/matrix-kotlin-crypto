import org.audriga.matrix.crypto.MessageEncryptionUtils.Companion.defaultEncryptionSettings
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine

class DemoUtils {
    companion object {
        internal fun createExampleEncryptedEvent(
            rustOlmMachine: RustOmlMachine,
            roomId: String,
            users: List<String>
        ): String {
            val settings = defaultEncryptionSettings()
            val shareRoomKeyRequests = rustOlmMachine.shareRoomKey(roomId, users, settings)
            // todo this is empty, no matter what I supply as users, and even when I set "onlyAllowTrustedDevices" to false in encryptionSettings.
            println("Share Room Key requests: $shareRoomKeyRequests")


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
            return encryptedEvent
        }

    }
}