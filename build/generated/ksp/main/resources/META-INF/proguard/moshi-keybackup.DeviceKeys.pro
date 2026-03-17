-keepnames class keybackup.DeviceKeys
-if class keybackup.DeviceKeys
-keep class keybackup.DeviceKeysJsonAdapter {
    public <init>(com.squareup.moshi.Moshi);
}
