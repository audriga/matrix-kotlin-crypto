package org.audriga.matrix.crypto

import keybackup.MoshiProvider

class JsonUtils {
    companion object {
        @JvmStatic
        fun Map<String, Any>.toJson(): String = MoshiProvider.providesMoshi().adapter(Map::class.java).toJson(this)
    }
}