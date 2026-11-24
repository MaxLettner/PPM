plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.peerpass"
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }

    defaultConfig {
        applicationId = "dev.peerpass"
        minSdk = 33
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Sideloaded personal build: sign with the debug key unless you configure your own.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true }
    packaging { jniLibs { useLegacyPackaging = false } }
}

// Builds the Rust core (cargo-ndk) and regenerates the UniFFI Kotlin bindings.
val buildRust by tasks.registering(Exec::class) {
    workingDir = rootProject.projectDir
    commandLine("./build-rust.sh")
}
tasks.named("preBuild") { dependsOn(buildRust) }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.11.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.1")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.work:work-runtime-ktx:2.12.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("net.java.dev.jna:jna:5.19.1@aar")
}
