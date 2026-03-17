-keepnames class keybackup.UploadSigningKeysBody
-if class keybackup.UploadSigningKeysBody
-keep class keybackup.UploadSigningKeysBodyJsonAdapter {
    public <init>(com.squareup.moshi.Moshi);
}
-if class keybackup.UploadSigningKeysBody
-keepnames class kotlin.jvm.internal.DefaultConstructorMarker
-keepclassmembers class keybackup.UploadSigningKeysBody {
    public synthetic <init>(keybackup.RestKeyInfo,keybackup.RestKeyInfo,keybackup.RestKeyInfo,java.util.Map,int,kotlin.jvm.internal.DefaultConstructorMarker);
}
