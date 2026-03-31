package org.audriga.matrix.crypto

import org.audriga.matrix.crypto.moshi.MoshiProvider
import org.matrix.android.sdk.api.session.room.model.message.MessageFileContent
import org.matrix.android.sdk.api.session.room.model.message.MessageImageContent
import org.matrix.android.sdk.api.session.room.model.message.MessageWithAttachmentContent

class JsonUtils {
    companion object {
        @JvmStatic
        fun Map<String, Any>.toJson(): String = MoshiProvider.providesMoshi().adapter(Map::class.java).toJson(this)

        @JvmStatic
        fun <T: MessageWithAttachmentContent> T.toJson(): String = MoshiProvider.providesMoshi().adapter(this.javaClass).toJson(this)
    }
}