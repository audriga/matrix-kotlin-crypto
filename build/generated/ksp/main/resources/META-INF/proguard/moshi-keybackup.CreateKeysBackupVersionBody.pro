-keepnames class keybackup.CreateKeysBackupVersionBody
-if class keybackup.CreateKeysBackupVersionBody
-keep class keybackup.CreateKeysBackupVersionBodyJsonAdapter {
    public <init>(com.squareup.moshi.Moshi);
}
