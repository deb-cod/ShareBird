# main.py
import os, socket, base64, threading, traceback
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from kivy.factory import Factory

from kivy.app import App
from kivy.lang import Builder
from kivy.properties import StringProperty, BooleanProperty
from kivy.uix.popup import Popup
from kivy.utils import platform

ANDROID = (platform == "android")
if ANDROID:
    from android.permissions import request_permissions, Permission
    from jnius import autoclass
    from android import mActivity

# ---------- Permissions / helpers ----------
def has_all_files_access() -> bool:
    if not ANDROID:
        return True
    try:
        Build_VERSION = autoclass('android.os.Build$VERSION')
        sdk = int(Build_VERSION.SDK_INT)
        if sdk >= 30:
            Environment = autoclass('android.os.Environment')
            return bool(Environment.isExternalStorageManager())
        return True
    except Exception:
        # Don't hard-fail: treat as allowed and rely on listdir test later.
        return True

def open_all_files_settings():
    if not ANDROID:
        return
    try:
        Intent = autoclass('android.content.Intent')
        Settings = autoclass('android.provider.Settings')
        Uri = autoclass('android.net.Uri')
        intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
        intent.setData(Uri.parse(f"package:{mActivity.getPackageName()}"))
        mActivity.startActivity(intent)
    except Exception:
        try:
            Intent = autoclass('android.content.Intent')
            Settings = autoclass('android.provider.Settings')
            intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
            mActivity.startActivity(intent)
        except Exception:
            pass

def ensure_storage_permission() -> bool:
    if not ANDROID:
        return True
    try:
        request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
    except Exception:
        pass
    return has_all_files_access()

# ---------- UI (safe folder picker) ----------
KV = r"""
#:import Clipboard kivy.core.clipboard.Clipboard
#:import dp kivy.metrics.dp

<SafeFolderPicker@Popup>:
    title: "Choose a folder"
    size_hint: 0.9, None
    height: dp(360)
    auto_dismiss: False
    BoxLayout:
        orientation: "vertical"
        spacing: dp(8)
        padding: dp(10)
        GridLayout:
            cols: 2
            spacing: dp(8)
            size_hint_y: None
            height: dp(200)
            Button:
                text: "/sdcard/Download"
                on_release: app.pick_quick("/sdcard/Download"); root.dismiss()
            Button:
                text: "/sdcard/Pictures"
                on_release: app.pick_quick("/sdcard/Pictures"); root.dismiss()
            Button:
                text: "/sdcard/DCIM"
                on_release: app.pick_quick("/sdcard/DCIM"); root.dismiss()
            Button:
                text: "/sdcard/Movies"
                on_release: app.pick_quick("/sdcard/Movies"); root.dismiss()
            Button:
                text: "/sdcard/Music"
                on_release: app.pick_quick("/sdcard/Music"); root.dismiss()
            Button:
                text: "/sdcard/Documents"
                on_release: app.pick_quick("/sdcard/Documents"); root.dismiss()
        Label:
            text: "Or enter a custom path:"
            size_hint_y: None
            height: dp(20)
        TextInput:
            id: custom_path
            multiline: False
            text: app.folder_path
            size_hint_y: None
            height: dp(40)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(8)
            Button:
                text: "Cancel"
                on_release: root.dismiss()
            Button:
                text: "Use this path"
                on_release: app.pick_custom(custom_path.text); root.dismiss()

BoxLayout:
    orientation: "vertical"
    padding: 12
    spacing: 10

    Label:
        text: "ShareBird (Kivy) — HTTP File Share"
        size_hint_y: None
        height: self.texture_size[1] + dp(6)

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: 8
        Label:
            text: "Folder"
            size_hint_x: None
            width: dp(60)
        TextInput:
            id: folder
            text: app.folder_path
            multiline: False
        Button:
            text: "Browse"
            size_hint_x: None
            width: dp(120)
            on_release: app.open_picker()

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: 8
        Label:
            text: "Port"
            size_hint_x: None
            width: dp(60)
        TextInput:
            id: port
            text: app.port_text
            input_filter: "int"
            multiline: False
        Label:
            text: "User"
            size_hint_x: None
            width: dp(50)
        TextInput:
            id: user
            text: app.user_text
            multiline: False
        Label:
            text: "Pass"
            size_hint_x: None
            width: dp(50)
        TextInput:
            id: pwd
            text: app.pass_text
            password: True
            multiline: False

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: 8
        Button:
            text: "Start Server"
            disabled: app.running
            on_release: app.start_server()
        Button:
            text: "Stop"
            disabled: not app.running
            on_release: app.stop_server()

    Label:
        text: "Diagnostics"
        size_hint_y: None
        height: self.texture_size[1] + dp(6)

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: 8
        Button:
            text: "Open All-files settings"
            on_release: app.open_all_files()
        Button:
            text: "Check access now"
            on_release: app.check_access()

    Label:
        text: "Share URL"
        size_hint_y: None
        height: self.texture_size[1] + dp(6)

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: 8
        TextInput:
            id: urlbox
            text: app.share_url
            readonly: True
        Button:
            text: "Copy"
            size_hint_x: None
            width: dp(100)
            on_release: Clipboard.copy(app.share_url)

    ScrollView:
        size_hint_y: None
        height: dp(150)
        do_scroll_x: False
        do_scroll_y: True
        Label:
            id: statuslbl
            text: app.status_text
            size_hint_y: None
            height: self.texture_size[1]
            halign: "left"
            valign: "top"
            text_size: self.width, None
"""

# ---------- Networking ----------
def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

# ---------- HTTP handler (with optional Basic Auth) ----------
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

class AuthHandler(SimpleHTTPRequestHandler):
    served_directory = None
    auth_token = None  # base64("user:pass") or None

    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=self.served_directory or directory, **kwargs)

    def _authed(self):
        if not self.auth_token:
            return True
        hdr = self.headers.get("Authorization")
        return hdr == f"Basic {self.auth_token}"

    def _ask(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Files"')
        self.end_headers()

    def do_HEAD(self):
        if not self._authed():
            self._ask(); return
        super().do_HEAD()

    def do_GET(self):
        if not self._authed():
            self._ask(); return
        super().do_GET()

    def list_directory(self, path):
        try:
            return super().list_directory(path)
        except Exception:
            return self.send_error(404, "No permission to list directory")

    def log_message(self, fmt, *args):
        # quiet
        pass

class ServerThread:
    def __init__(self, host, port, directory, user=None, pwd=None):
        self.host = host; self.port = port; self.directory = directory
        self.user = user; self.pwd = pwd
        self.httpd = None; self.thread = None

    def start(self):
        AuthHandler.served_directory = self.directory
        if self.user and self.pwd:
            token = base64.b64encode(f"{self.user}:{self.pwd}".encode()).decode()
            AuthHandler.auth_token = token
        else:
            AuthHandler.auth_token = None
        Handler = partial(AuthHandler, directory=self.directory)
        self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

# ---------- App ----------
class ShareApp(App):
    folder_path = StringProperty("/storage/emulated/0/Download" if ANDROID
                                 else os.path.join(os.path.expanduser("~"), "Downloads"))
    port_text  = StringProperty("8000")
    user_text  = StringProperty("")
    pass_text  = StringProperty("")
    share_url  = StringProperty("—")
    status_text= StringProperty("Pick a folder and press Start.")
    running    = BooleanProperty(False)

    def build(self):
        ensure_storage_permission()
        return Builder.load_string(KV)

    # Safe picker actions
    def open_picker(self):
        # instantiate the KV rule class
        Factory.SafeFolderPicker().open()

    def pick_quick(self, path):
        self.folder_path = path
        self.status_text = f"Selected: {path}"

    def pick_custom(self, path):
        path = (path or "").strip()
        if not path:
            self.status_text = "No path entered."
            return
        self.folder_path = path
        self.status_text = f"Selected: {path}"

    def open_all_files(self):
        open_all_files_settings()

    def check_access(self):
        msgs = []
        try:
            msgs.append(f"Android: {ANDROID}")
            if ANDROID:
                Build_VERSION = autoclass('android.os.Build$VERSION')
                sdk = int(Build_VERSION.SDK_INT)
                msgs.append(f"SDK: {sdk}")
                msgs.append(f"All-files access: {has_all_files_access()}")
        except Exception as e:
            msgs.append(f"SDK check err: {e}")

        paths = [self.folder_path.strip()]
        if paths[0].startswith("/storage/emulated/0"):
            paths.append(paths[0].replace("/storage/emulated/0", "/sdcard", 1))

        for p in paths:
            try:
                if not os.path.isdir(p):
                    msgs.append(f"[X] Not a dir: {p}")
                    continue
                names = os.listdir(p)
                preview = ", ".join(names[:10])
                msgs.append(f"[✓] {p} -> {len(names)} entries")
                msgs.append(f"    {preview}{' ...' if len(names) > 10 else ''}")
            except Exception as e:
                msgs.append(f"[!] listdir failed for {p}: {e}")
        self.status_text = "\n".join(msgs)

    def start_server(self):
        directory = self.folder_path.strip()
        if ANDROID and directory.startswith("/storage/emulated/0"):
            alt = directory.replace("/storage/emulated/0", "/sdcard", 1)
            if os.path.isdir(alt):
                directory = alt

        if not os.path.isdir(directory):
            self.status_text = f"Folder not found or no permission:\n{directory}"
            return

        try:
            entries = os.listdir(directory)
            self.status_text = f"Directory ok: {directory}  (entries: {len(entries)})"
        except Exception as e:
            self.status_text = (f"Cannot read this folder:\n{directory}\n{e}\n"
                                "Tip: tap 'Open All-files settings' and enable the toggle.")
            return

        try:
            port = int(self.port_text)
            if not (1 <= port <= 65535): raise ValueError()
        except Exception:
            self.status_text = "Invalid port. Use 1–65535 (e.g., 8000)."
            return

        self._server = ServerThread(
            host="0.0.0.0",
            port=port,
            directory=directory,
            user=(self.user_text.strip() or None),
            pwd=(self.pass_text.strip() or None),
        )
        try:
            self._server.start()
        except OSError as e:
            self.status_text = f"Could not start (port in use or blocked):\n{e}"
            return

        ip = get_lan_ip()
        self.share_url = f"http://{ip}:{port}/"
        self.running = True
        self.status_text += (f"\n\nServing:\n{directory}\nOpen on same LAN:\n{self.share_url}\n"
                             f"Tip: keep screen awake for big transfers.")

    def stop_server(self):
        try:
            if getattr(self, "_server", None):
                self._server.stop()
        finally:
            self.running = False
            self.share_url = "—"
            self.status_text = "Stopped."
            self._server = None

if __name__ == "__main__":
    ShareApp().run()
