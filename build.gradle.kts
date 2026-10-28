// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    // --- Kotlin Multiplatform (module :shared, partagé Android + iOS) ---
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.sqldelight) apply false
}
