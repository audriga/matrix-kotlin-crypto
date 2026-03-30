package org.audriga.matrix.crypto

import keybackup.MoshiProvider
import org.matrix.android.sdk.api.session.room.model.message.MessageImageContent

class JsonUtils {
    companion object {
        @JvmStatic
        fun Map<String, Any>.toJson(): String = MoshiProvider.providesMoshi().adapter(Map::class.java).toJson(this)

        @JvmStatic
        fun MessageImageContent.toJson(): String = MoshiProvider.providesMoshi().adapter(MessageImageContent::class.java).toJson(this)
    }
}