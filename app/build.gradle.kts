plugins {
    id("com.android.application")
}

android {
    namespace = "com.config.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.config.vpnadblock"
        minSdk = 26
        targetSdk = 36
        versionCode = 17
        versionName = "6.0.0-alpha17"
    }

    signingConfigs {
        create("release") {
            // Phase A: fresh upload keystore for ConfigVPNAdBlock (свой ключ,
            // не из ConfigAdBlock). Пароли переопределяются env/project props.
            // v1 ОТКЛЮЧЕН: в zip-структуре APK есть файлы с именами, которые
            // ломают JAR-валидацию v1 → «пакет недействителен» при установке.
            // v2+v3 достаточно для Android 7.0+ (minSdk 26).
            enableV1Signing = false
            enableV2Signing = true
            enableV3Signing = true
            storeFile = file(System.getenv("UPLOAD_KEYSTORE_PATH")
                ?: (project.findProperty("UPLOAD_KEYSTORE_PATH") as String?)
                ?: "cvab-upload.jks")
            storePassword = System.getenv("UPLOAD_STORE_PASSWORD") ?: "cvab-upload-2026"
            keyAlias = System.getenv("UPLOAD_KEY_ALIAS") ?: "cvab-upload"
            keyPassword = System.getenv("UPLOAD_KEY_PASSWORD") ?: "cvab-upload-2026"
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }


}

dependencies {
    // AdBlock engine (gomobile AAR, собирается CI из mitm/ — beta7 37c49e4c)
    implementation(files("libs/mitm.aar"))

    testImplementation("junit:junit:4.13.2")
    // Реальная реализация org.json для юнит-тестов: без неё классы берутся
    // из заглушечного android.jar и бросают "not mocked", из-за чего
    // jsonToServer молча возвращал null (падал тест D).
    testImplementation("org.json:json:20240303")

    implementation("com.zaneschepke:amneziawg-android:2.3.7")
    implementation("com.wireguard.android:tunnel:1.0.20260102")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.drawerlayout:drawerlayout:1.2.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.jcraft:jsch:0.1.55")
}
