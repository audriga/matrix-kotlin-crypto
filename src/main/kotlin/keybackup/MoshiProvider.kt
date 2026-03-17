package keybackup

import com.squareup.moshi.Moshi
import com.squareup.moshi.adapters.PolymorphicJsonAdapterFactory
import org.matrix.android.sdk.api.session.identity.ThreePid
import org.matrix.android.sdk.api.session.room.model.message.MessageAudioContent
import org.matrix.android.sdk.api.session.room.model.message.MessageContent
import org.matrix.android.sdk.api.session.room.model.message.MessageDefaultContent
import org.matrix.android.sdk.api.session.room.model.message.MessageEmoteContent
import org.matrix.android.sdk.api.session.room.model.message.MessageFileContent
import org.matrix.android.sdk.api.session.room.model.message.MessageImageContent
import org.matrix.android.sdk.api.session.room.model.message.MessageLocationContent
import org.matrix.android.sdk.api.session.room.model.message.MessageNoticeContent
import org.matrix.android.sdk.api.session.room.model.message.MessagePollResponseContent
import org.matrix.android.sdk.api.session.room.model.message.MessageTextContent
import org.matrix.android.sdk.api.session.room.model.message.MessageType
import org.matrix.android.sdk.api.session.room.model.message.MessageVerificationRequestContent
import org.matrix.android.sdk.api.session.room.model.message.MessageVideoContent



internal object MoshiProvider {

    private val moshi: Moshi = Moshi.Builder()
//        .add(UriMoshiAdapter())
        .add(ForceToBooleanJsonAdapter())
        .add(CipherSuiteMoshiAdapter())
        .add(TlsVersionMoshiAdapter())
        // Use addLast here so we can inject a SplitLazyRoomSyncJsonAdapter later to override the default parsing.
        .addLast(DefaultLazyRoomSyncEphemeralJsonAdapter())
        .add(
            RuntimeJsonAdapterFactory.of(MessageContent::class.java, "msgtype", MessageDefaultContent::class.java)
                .registerSubtype(MessageTextContent::class.java, MessageType.MSGTYPE_TEXT)
                .registerSubtype(MessageNoticeContent::class.java, MessageType.MSGTYPE_NOTICE)
                .registerSubtype(MessageEmoteContent::class.java, MessageType.MSGTYPE_EMOTE)
                .registerSubtype(MessageAudioContent::class.java, MessageType.MSGTYPE_AUDIO)
                .registerSubtype(MessageImageContent::class.java, MessageType.MSGTYPE_IMAGE)
                .registerSubtype(MessageVideoContent::class.java, MessageType.MSGTYPE_VIDEO)
                .registerSubtype(MessageLocationContent::class.java, MessageType.MSGTYPE_LOCATION)
                .registerSubtype(MessageFileContent::class.java, MessageType.MSGTYPE_FILE)
                .registerSubtype(MessageVerificationRequestContent::class.java, MessageType.MSGTYPE_VERIFICATION_REQUEST)
                .registerSubtype(MessagePollResponseContent::class.java, MessageType.MSGTYPE_POLL_RESPONSE)
        )
        .add(SerializeNulls.JSON_ADAPTER_FACTORY)
        .add(
            PolymorphicJsonAdapterFactory.of(ThreePid::class.java, "type")
                .withSubtype(ThreePid.Email::class.java, "email")
                .withSubtype(ThreePid.Msisdn::class.java, "msisdn")
                .withDefaultValue(null)
        )
        .build()

    fun providesMoshi(): Moshi {
        return moshi
    }
}
