import org.matrix.android.sdk.api.Matrix

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
fun main() {
    val version = org.matrix.rustcomponents.sdk.crypto.version()
    val cryptoVersion = Matrix.getCryptoVersion(longFormat = true)

    //TIP Press <shortcut actionId="ShowIntentionActions"/> with your caret at the highlighted text
    // to see how IntelliJ IDEA suggests fixing it.
    println("version, $version!")
    println("cryptoVersion, $cryptoVersion!")

}