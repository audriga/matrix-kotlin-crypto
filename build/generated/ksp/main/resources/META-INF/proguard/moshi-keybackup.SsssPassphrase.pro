-keepnames class keybackup.SsssPassphrase
-if class keybackup.SsssPassphrase
-keep class keybackup.SsssPassphraseJsonAdapter {
    public <init>(com.squareup.moshi.Moshi);
}
