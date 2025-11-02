# buildozer.spec
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

# permissions
android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,MANAGE_EXTERNAL_STORAGE

# (optional) keep screen on while running
# android.wakelock = True

# target
android.api = 34
android.minapi = 26
