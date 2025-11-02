[app]
title = ShareBird
package.name = httpfileshare
package.domain = com.example
source.dir = .
source.include_exts = py,kv,txt,ini
version = 0.0.4

requirements = python3,kivy
orientation = portrait
fullscreen = 0

android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,MANAGE_EXTERNAL_STORAGE
android.grant_permissions = True
android.archs = arm64-v8a

android.api = 34
android.minapi = 26

# Optional
# android.wakelock = True

# ✅ Android 10 only (API 29): request legacy external storage
android.add_manifest_application_arguments = android:requestLegacyExternalStorage="true"
