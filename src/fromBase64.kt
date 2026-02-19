import kotlin.io.encoding.Base64

// Replaces the extension function used by the top level matrix library, since
// `org.matrix.android.sdk.api.util.fromBase64` requires android
fun String.fromBase64(): ByteArray {
    return Base64.decode(this)
}
