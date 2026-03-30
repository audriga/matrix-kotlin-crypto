package org.audriga.matrix.crypto.keybackup//import androidx.annotation.VisibleForTesting
import keybackup.MoshiProvider
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.util.TreeSet
import kotlin.collections.iterator
import java.util.logging.Level
import java.util.logging.Logger

// Copied from package org.matrix.android.sdk.internal.util
/**
 * Build canonical Json
 * Doc: https://matrix.org/docs/spec/appendices.html#canonical-json
 */
internal object JsonCanonicalizer {
    private val mLogger = Logger.getLogger(JsonCanonicalizer::class.java.name)

    fun <T> getCanonicalJson(type: Class<T>, o: T): String {
        val adapter = MoshiProvider.providesMoshi().adapter<T>(type)

        // Canonicalize manually
        return canonicalize(adapter.toJson(o))
            .replace("\\/", "/")
    }

//    @VisibleForTesting
    fun canonicalize(jsonString: String): String {
        return try {
            val jsonObject = JSONObject(jsonString)

            canonicalizeRecursive(jsonObject)
        } catch (e: JSONException) {
            mLogger.log(Level.WARNING, "Unable to canonicalize", e)
            jsonString
        }
    }

    /**
     * Canonicalize a JSON element.
     *
     * @param any the src
     * @return the canonicalize element
     */
    private fun canonicalizeRecursive(any: Any): String {
        when (any) {
            is JSONArray -> {
                // Canonicalize each element of the array
                return (0 until any.length()).joinToString(separator = ",", prefix = "[", postfix = "]") {
                    canonicalizeRecursive(any.get(it))
                }
            }
            is JSONObject -> {
                // Sort the attributes by name, and the canonicalize each element of the JSONObject

                val attributes = TreeSet<String>()
                for (entry in any.keys()) {
                    attributes.add(entry)
                }

                return buildString {
                    append("{")
                    for ((index, value) in attributes.withIndex()) {
                        append("\"")
                        append(value)
                        append("\"")
                        append(":")
                        append(canonicalizeRecursive(any[value]))

                        if (index < attributes.size - 1) {
                            append(",")
                        }
                    }
                    append("}")
                }
            }
            is String -> return JSONObject.quote(any)
            else -> return any.toString()
        }
    }
}
