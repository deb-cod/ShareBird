# main.py
import threading
import socket
import base64
import os
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from kivy.app import App
from kivy.lang import Builder
from kivy.properties import StringProperty, BooleanProperty
from kivy.clock import mainthread
from kivy.utils import platform

# Optional permissions (Android)
try:
    if platform == "android":
        from android.permissions import request_permissions, Permission
except Exception:
    pass

KV = r"""
#:import Clipboard kivy.core.clipboard.Clipboard
BoxLayout:
    orientation: "vertical"
    padding: 12
    spacing: 10

    Label:
        text: "Android HTTP File Share (Python/Kivy)"
        size_hint_y: None
        height: self.texture_size[1] + dp(6)
        bold: True

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: 8
        Label:
            text: "Folder"
            size_hint_x: None
            width: dp(80)
        TextInput:
            id: folder
            text: app.folder_path
            multiline: False
        Button:
            text: "Use Download"
            size_hint_x: None
            width: dp(130)
            on_release: app.use_download()

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: 8
        Label:
            text: "Port"
            size_hint_x: None
            width: dp(80)
        TextInput:
            id: port
            text: app.port_text
            input_filter: "int"
            multiline: False
        Label:
            text: "User"
            size_hint_x: None
            width: dp(60)
        TextInput:
            id: user
            text: app.user_text
            multiline: False
        Label:
            text: "Pass"
            size_hint_x: None
            width: dp(60)
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
            id: startbtn
            text: "Start Server"
            on_release: app.start_server()
            disabled: app.running
        Button:
            id: stopbtn
            text: "Stop"
            on_release: app.stop_server()
            disabled: not app.running

    Label:
        text: "Share URL"
        size_hint_y: None
        height: self.texture_size[1] + dp(6)
        bold: True

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
            on_release:
                Clipboard.copy(app.share_url)

    Label:
        text: app.status_text
        size_hint_y: None
        height: dp(60)
        halign: "left"
        valign: "top"
        text_size: self.size
"""

# ---------------- networking helpers ----------------
def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

# --------------- HTTP handler with Basic Auth ----------
class AuthHandler(SimpleHTTPRequestHandler):
    served_directory = None
    auth_token = None  # "user:pass" in base64, or None (no auth)

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
            self._ask()
            return
        super().do_HEAD()

    def do_GET(self):
        if not self._authed():
            self._ask()
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        # quiet logs; comment next line to see requests in logcat
        pass

class ServerThread:
    def __init__(self, host, port, directory, user=None, pwd=None):
        self.host = host
        self.port = port
        self.directory = directory
        self.user = user
        self.pwd = pwd
        self.httpd = None
        self.thread = None

    def start(self):
        # configure handler
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

# ------------------- Kivy App -------------------------
class ShareApp(App):
    folder_path = StringProperty("/storage/emulated/0/Download")
    # folder_path = StringProperty(r"E:\ShareBird\bin")
    port_text = StringProperty("8000")
    user_text = StringProperty("")
    pass_text = StringProperty("")
    share_url = StringProperty("—")
    status_text = StringProperty("Pick a folder and press Start.")
    running = BooleanProperty(False)

    def build(self):
        # Ask permissions on Android
        if platform == "android":
            try:
                request_permissions([
                    Permission.READ_EXTERNAL_STORAGE,
                    Permission.WRITE_EXTERNAL_STORAGE,
                    # On Android 11+ you may need this for full access:
                    Permission.MANAGE_EXTERNAL_STORAGE,
                ])
            except Exception:
                pass
        return Builder.load_string(KV)

    def use_download(self):
        self.folder_path = "/storage/emulated/0/Download"

    @mainthread
    def _set_status(self, msg):
        self.status_text = msg

    def start_server(self):
        # validate dir
        directory = self.folder_path.strip()
        if not os.path.isdir(directory):
            self._set_status(f"Folder not found:\n{directory}")
            return

        # validate port
        try:
            port = int(self.port_text)
            if not (1 <= port <= 65535):
                raise ValueError()
        except Exception:
            self._set_status("Invalid port. Use 1–65535 (e.g., 8000).")
            return

        # spin server
        self._server = ServerThread(
            host="0.0.0.0",
            port=port,
            directory=directory,
            user=self.user_text.strip() or None,
            pwd=self.pass_text.strip() or None,
        )
        try:
            self._server.start()
        except OSError as e:
            self._set_status(f"Could not start (port in use or blocked):\n{e}")
            return

        ip = get_lan_ip()
        self.share_url = f"http://{ip}:{port}/"
        self.running = True
        self._set_status(f"Serving:\n{directory}\n\nOpen this on your PC/phone:\n{self.share_url}\n\n"
                         f"Tip: keep screen awake for big transfers.")

    def stop_server(self):
        try:
            if hasattr(self, "_server") and self._server:
                self._server.stop()
        finally:
            self.running = False
            self.share_url = "—"
            self._set_status("Stopped.")
            self._server = None

if __name__ == "__main__":
    ShareApp().run()
