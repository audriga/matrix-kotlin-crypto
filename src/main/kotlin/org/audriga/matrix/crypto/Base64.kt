package org.audriga.matrix.crypto

import kotlin.io.encoding.Base64

// Replaces the extension function used by the top level matrix library, since
// `org.matrix.android.sdk.api.util.fromBase64` requires android

fun ByteArray.toBase64NoPadding(): String {
//    return Base64.encodeToString(this, Base64.NO_PADDING or Base64.NO_WRAP)
    return Base64.withPadding(Base64.PaddingOption.ABSENT).encode(this)
//    return Base64(
//        isUrlSafe = false,
//        isMimeScheme = false,
//        mimeLineLength = -1,
//        paddingOption = Base64.PaddingOption.ABSENT
//    ).encode(this)
}

fun ByteArray.toBase64Url() : String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(this)

fun String.fromBase64Url() : ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(this)

//fun String.fromBase64(): ByteArray {
//    return Base64.decode(this)
//}

fun String.fromBase64NoPadding(): ByteArray {
    return Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(this)
}