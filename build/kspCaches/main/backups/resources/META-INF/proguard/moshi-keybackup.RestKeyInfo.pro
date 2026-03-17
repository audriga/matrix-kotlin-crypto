-keepnames class keybackup.RestKeyInfo
-if class keybackup.RestKeyInfo
-keep class keybackup.RestKeyInfoJsonAdapter {
    public <init>(com.squareup.moshi.Moshi);
}
-if class keybackup.RestKeyInfo
-keepnames class kotlin.jvm.internal.DefaultConstructorMarker
-keepclassmembers class keybackup.RestKeyInfo {
    public synthetic <init>(java.lang.String,java.util.List,java.util.Map,java.util.Map,int,kotlin.jvm.internal.DefaultConstructorMarker);
}
