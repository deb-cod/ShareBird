[app]
title = ShareBird
package.name = httpfileshare
package.domain = com.example
source.dir = .
source.include_exts = py,kv,txt,ini
version = 0.0.1

requirements = python3,kivy
orientation = portrait
fullscreen = 0

# ✅ Permissions (already present)
android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,MANAGE_EXTERNAL_STORAGE

# ✅ Auto-grant runtime perms on deploy (debug convenience)
android.grant_permissions = True

# ✅ Build only arm64 (faster, most modern phones)
android.archs = arm64-v8a

# target
android.api = 34
android.minapi = 26

# (optional) keep screen on while running
# android.wakelock = True

# (optional) Android 10 only (API 29): request legacy external storage
# This helps on Android 10 devices; harmless elsewhere.
# android.add_manifest_xml = <application android:requestLegacyExternalStorage="true"/>
