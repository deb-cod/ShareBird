# main.py
import os, socket, base64, threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from kivy.app import App
from kivy.lang import Builder
from kivy.properties import StringProperty, BooleanProperty
from kivy.uix.popup import Popup
from kivy.uix.boxlayout import BoxLayout
from kivy.utils import platform

ANDROID = (platform == "android")
if ANDROID:
    from android.permissions import request_permissions, Permission
    from jnius import autoclass
    from android import mActivity

def ensure_storage_permission() -> bool:
    if not ANDROID:
        return True
    try:
        request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
    except Exception:
        pass
    try:
        Build = autoclass('android.os.Build')
        if Build.VERSION.SDK_INT >= 30:
            Environment = autoclass('android.os.Environment')
            if not Environment.isExternalStorageManager():
                Intent = autoclass('android.content.Intent')
                Settings = autoclass('android.provider.Settings')
                Uri = autoclass('android.net.Uri')
                intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.setData(Uri.parse(f"package:{mActivity.getPackageName()}"))
                mActivity.startActivity(intent)
                return False
    except Exception:
        pass
    return True

KV = r"""
#:import Clipboard kivy.core.clipboard.Clipboard
#:import dp kivy.metrics.dp

<FilePickerPopup>:
    title: "Pick a folder"
    size_hint: 0.9, 0.9
    auto_dismiss: False
    BoxLayout:
        orientation: "vertical"
        spacing: dp(8)
        padding: dp(8)
        FileChooserListView:
            id: chooser
            dirselect: True
            path: app.folder_path
            filters: []
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(8)
            Button:
                text: "Cancel"
                on_release: root.dismiss()
            Button:
                text: "Use this folder"
                on_release: root.select_dir(chooser.path if chooser.path else chooser.current_path)

BoxLayout:
    orientation: "vertical"
    padding: 12
    spacing: 10

    Label:
        text: "HTTP File Share (Kivy)"
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

    Label:
        id: statuslbl
        text: app.status_text
        size_hint_y: None
        height: dp(60)
        halign: "left"
        valign: "top"
        text_size: self.size
"""

def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

class AuthHandler(SimpleHTTPRequestHandler):
    served_directory = None
    auth_token = None

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

class FilePickerPopup(Popup):
    def select_dir(self, path):
        if path:
            App.get_running_app().folder_path = path
        self.dismiss()

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

    def open_picker(self):
        FilePickerPopup().open()

    def start_server(self):
        if not ensure_storage_permission() and ANDROID:
            self.status_text = ("Please enable 'All files access' for this app, "
                                "then return and press Start again.")
            return

        directory = self.folder_path.strip()
        if ANDROID and directory.startswith("/storage/emulated/0"):
            alt = directory.replace("/storage/emulated/0", "/sdcard", 1)
            if os.path.isdir(alt):
                directory = alt

        if not os.path.isdir(directory):
            self.status_text = f"Folder not found or no permission:\n{directory}"
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
        self.status_text = (f"Serving:\n{directory}\n\nOpen on any device in same LAN:\n"
                            f"{self.share_url}\n\nTip: keep screen awake for big transfers.")

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
