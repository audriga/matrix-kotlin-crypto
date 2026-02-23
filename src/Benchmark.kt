import org.matrix.rustcomponents.sdk.crypto.EncryptionSettings
import org.matrix.rustcomponents.sdk.crypto.EventEncryptionAlgorithm
import org.matrix.rustcomponents.sdk.crypto.HistoryVisibility
import kotlin.system.exitProcess
import kotlin.time.measureTime
import org.matrix.rustcomponents.sdk.crypto.OlmMachine as RustOmlMachine

fun main() {

    val olmMachinePath = "/tmp/olmMachine"
    val rustOlmMachine: RustOmlMachine
    val timeTakenInitOlmMachine = measureTime {
        rustOlmMachine = RustOmlMachine("@alice:ZetaHorologii", "migDevice", olmMachinePath, null)
    }
    println("Time to create olm machine $timeTakenInitOlmMachine")

    val timeTakenToInitOlmSession = measureTime {
        val settings = EncryptionSettings(
            algorithm = EventEncryptionAlgorithm.MEGOLM_V1_AES_SHA2,
            onlyAllowTrustedDevices = true,
            rotationPeriod = 604800000.toULong(),
            rotationPeriodMsgs = 100000.toULong(),
            historyVisibility = HistoryVisibility.SHARED,
            errorOnVerifiedUserProblem = false,
        )
        rustOlmMachine.shareRoomKey(roomId, listOf(), settings)
    }
    println("Time to init megolm session $timeTakenToInitOlmSession")

    val eventType = "m.room.message"
    val content = """
            {
             "msgtype": "m.text",
             "body": "Encrypted hi from API"
            }
        """.trimIndent()

    val timeTakenToEncryptX1000 = measureTime {
        val encryptedEvents = arrayOfNulls<String>(1000)
        for (i in 0..< 1000) {
            encryptedEvents[i] = rustOlmMachine.encrypt(
                roomId,
                eventType,
                content,)
        }
    }
    println("Time to encrypt 1000 messages $timeTakenToEncryptX1000")
    exitProcess(0)
}