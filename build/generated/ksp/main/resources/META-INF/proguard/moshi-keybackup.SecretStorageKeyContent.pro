-keepnames class keybackup.SecretStorageKeyContent
-if class keybackup.SecretStorageKeyContent
-keep class keybackup.SecretStorageKeyContentJsonAdapter {
    public <init>(com.squareup.moshi.Moshi);
}
-if class keybackup.SecretStorageKeyContent
-keepnames class kotlin.jvm.internal.DefaultConstructorMarker
-keepclassmembers class keybackup.SecretStorageKeyContent {
    public synthetic <init>(java.lang.String,java.lang.String,keybackup.SsssPassphrase,java.lang.String,java.util.Map,int,kotlin.jvm.internal.DefaultConstructorMarker);
}
