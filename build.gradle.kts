plugins {
    kotlin("jvm") version "2.3.0"
    id("com.google.devtools.ksp") version "2.3.5"
//    id("com.gradleup.shadow") version "9.4.0" // needed for fat-jar
}

group = "org.audriga"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("lib/matrix-android-sdk2-1.6.50.jar"))
    implementation(files("lib/crypto-android-26.1.28.jar"))
    implementation("net.java.dev.jna:jna:5.18.1")
    implementation("com.squareup.moshi:moshi:1.15.2")
    implementation("com.squareup.moshi:moshi-adapters:1.15.2")
    implementation("com.squareup.okhttp3:okhttp:5.3.2")
    implementation("org.json:json:20251224")
//    implementation("com.squareup.moshi:moshi-kotlin-codegen:1.15.2")
    ksp("com.squareup.moshi:moshi-kotlin-codegen:1.15.2")
    testImplementation(kotlin("test"))
}


kotlin {
    jvmToolchain(25)
}

tasks.test {
    useJUnitPlatform()
}