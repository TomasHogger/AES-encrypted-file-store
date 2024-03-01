import cgi
import collections.abc
import datetime
import os
import shutil
import webbrowser
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Optional
from urllib import parse

from Crypto import Random

from constants import MAX_INACTIVE_TIME_SECONDS, PORT, CONTENT_PATH, META_PATH, KEY_PATH, ENCRYPTED_FILE_PREFIX, \
    TEMP_PATH
from encrypter import ENCODING, decrypt_path, decrypt, decrypt_stream, BinaryIOBytesInStream, BinaryIOBytesOutStream, \
    InMemoryBytesOutStream, encrypt, encrypt_name, decrypt_name, convert_size_of_encrypted_to_real_size, \
    encrypt_stream, encrypt_content

LAST_ACCESS_TIME = datetime.datetime.fromtimestamp(1)
KEY: Optional[bytes] = None

FAVICON = 'favicon.ico'

LOGOUT = 'logout'
NEXT = 'next'
PREV = 'prev'
BACK = 'back'

LOGIN_PAGE = '/login'
LOGOUT_PAGE = '/' + LOGOUT
CHANGE_PASSWORD_PAGE = '/change_password'

SAVE_REQUEST = 'save'
CREATE_REQUEST = 'create'
PROCESS_NOT_ENCRYPTED_REQUEST = 'process_not_encrypted'
CLEAR_TEMP_REQUEST = 'clear_temp'

PASSWORD_PARAM = "password"
AGAIN_PARAM = "again"
DIR_PARAM = "dir"
FILE_PARAM = "file"

LOGOUT_EL = f'<a id={LOGOUT} href="{LOGOUT_PAGE}">Logout</a>'
# noinspection JSUnresolvedReference
# language=HTML
COMMON_SCRIPT = f'''<script>
let inactiveTime = 0,
    startTimer = () => setInterval(() => {{
        inactiveTime++;
        if (inactiveTime > {MAX_INACTIVE_TIME_SECONDS}) {{
            document.getElementById("{LOGOUT}").click()
        }}
    }}, 1000),
    timer = startTimer();

window.onfocus = () => inactiveTime = 0;
window.onclick = () => inactiveTime = 0;

document.querySelectorAll("video").forEach(it => {{
    it.addEventListener("play", () => clearInterval(timer))
    it.addEventListener("pause", () => timer = startTimer())
}})

window.onkeydown = (event) => {{
    switch (event.key) {{
        case "ArrowRight":
            document.getElementById("{NEXT}").click()
            break
        case "ArrowLeft":
            document.getElementById("{PREV}").click()
            break
        case 'Backspace':
            document.getElementById("{BACK}").click()
            break
        case '.':
        case '/':
            document.getElementById("{LOGOUT}").click()
            break
    }}
}}
</script>'''


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class DirectoryEntry:
    def __init__(self, name: str, relative_path: str):
        self.name = name
        self.relative_path = relative_path


class Directory:
    def __init__(self, path: str | Path):
        self.path = path
        self.dirs: list[DirectoryEntry] = []
        self.files: list[DirectoryEntry] = []
        self.not_encrypted: list[str] = []

        self.init()

    def init(self):
        for entry in os.listdir(self.path):
            if not entry.startswith(ENCRYPTED_FILE_PREFIX):
                self.not_encrypted.append(entry)
                continue

            name = decrypt_name(KEY, entry)
            if os.path.isdir(os.path.join(self.path, entry)):
                self.dirs.append(DirectoryEntry(name, entry))
            else:
                self.files.append(DirectoryEntry(name, entry))

    def sorted_dirs(self) -> list[DirectoryEntry]:
        return sorted(self.dirs, key=lambda x: x.name)

    def sorted_files(self) -> list[DirectoryEntry]:
        return sorted(self.files, key=lambda x: x.name)


def validate_timeout():
    global KEY
    if (datetime.datetime.now() - LAST_ACCESS_TIME).seconds >= MAX_INACTIVE_TIME_SECONDS:
        KEY = None
    update_last_access_time()


def update_last_access_time():
    global LAST_ACCESS_TIME
    LAST_ACCESS_TIME = datetime.datetime.now()


class CustomRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, directory=CONTENT_PATH)
        self._headers_buffer = []

    def get_content_length(self) -> int:
        return int(self.headers['Content-Length'])

    def get_form_data(self):
        data = self.rfile.read(self.get_content_length())
        data = data.decode(ENCODING)
        data = parse.unquote(data)
        data = data.split('&')
        dict_data = dict()
        for item in data:
            variable, value = item.split('=')
            dict_data[variable] = value
        return dict_data

    def add_default_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')

    def send_response_only(self, code, message=None):
        """Send the response header only."""
        if self.request_version != 'HTTP/0.9':
            if message is None:
                if code in self.responses:
                    message = self.responses[code][0]
                else:
                    message = ''
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            self._headers_buffer.append(('%s %d %s\r\n' % (self.protocol_version, code, message))
                                        .encode(ENCODING, 'strict'))

    def send_header(self, keyword, value):
        """Send a MIME header to the headers buffer."""
        if self.request_version != 'HTTP/0.9':
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            self._headers_buffer.append(('%s: %s\r\n' % (keyword, value)).encode(ENCODING, 'strict'))

        if keyword.lower() == 'connection':
            if value.lower() == 'close':
                self.close_connection = True
            elif value.lower() == 'keep-alive':
                self.close_connection = False

    def send_text(self, resp: collections.abc.Sequence[str]):
        resp = '\n'.join(resp).encode(ENCODING)

        self.send_response(200)
        self.add_default_headers()
        self.send_header('Content-type', f'text/html; charset={ENCODING}')
        self.send_header('Content-Length', str(len(resp)))
        self.end_headers()

        self.wfile.write(resp)

    def send_reload(self):
        self.send_response(302)
        self.add_default_headers()
        self.send_header('Location', self.path)
        self.end_headers()

    def send_preview_page(self):
        location = self.path.rsplit('/', 1)[0] + '/'
        self.send_response(302)
        self.add_default_headers()
        self.send_header('Location', location)
        self.end_headers()

    def send_redirect_login(self):
        self.send_response(302)
        self.add_default_headers()
        self.send_header('Location', LOGIN_PAGE)
        self.end_headers()

    def send_main_page(self):
        self.send_response(302)
        self.add_default_headers()
        self.send_header('Location', '/')
        self.end_headers()

    def send_directory(self):
        # noinspection HtmlUnknownTarget
        # language=HTML
        resp = [f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>File List</title>
        </head>
        <body>
            {LOGOUT_EL}
            {'' if self.path == '/' else f'<a id="{BACK}" style="margin-left: 5px" href="..">Back</a>'}
            <a href="{PROCESS_NOT_ENCRYPTED_REQUEST}" style="margin-left: 5px">Process not encrypted</a>
            <a href="{CHANGE_PASSWORD_PAGE}" style="margin-left: 5px">Change password</a>
            <a href="{CLEAR_TEMP_REQUEST}" style="margin-left: 5px">Clear temp</a>
            <br/>
            <h2>Current Directory: {decrypt_path(KEY, self.path)}</h2>

            <form method="POST" action="{SAVE_REQUEST}" enctype=multipart/form-data>
                <input required name="{FILE_PARAM}" type="file" multiple/>
                <input type="submit" value="Add"/>
            </form>
            <form  method="POST" action="{CREATE_REQUEST}" style="margin-top: 5px">
                <input required name="{DIR_PARAM}" placeholder="Directory" type="text"/>
                <input type="submit" value="Create"/>
            </form>
            <br/>
            {COMMON_SCRIPT}
        ''']

        directory = Directory(self.translate_path(self.path))

        for e in directory.sorted_dirs():
            resp.append(f'<li><a href="{e.relative_path}/">[Dir] {e.name}</a></li>')
        for e in directory.sorted_files():
            resp.append(f'<li><a href="{e.relative_path}">{e.name}</a></li>')
        for e in directory.not_encrypted:
            resp.append(f'<li>[Not encrypted] {e}</li>')

        resp.append('''
            </ul>
        </body>
        </html>
        ''')

        self.send_text(resp)

    def send_file(self):
        path = self.translate_path(self.path)

        file_size = convert_size_of_encrypted_to_real_size(os.path.getsize(path))

        range_header = self.headers['Range']
        download_range = self.headers['Range']
        start = int(download_range.replace('bytes=', '').split('-')[0]) if download_range else 0

        if range_header:
            self.send_response(206)
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Range', f'bytes {start}-{file_size - 1}/{file_size}')
        else:
            self.send_response(200)
            self.send_header(
                'Content-Disposition',
                f'attachment; filename="{decrypt_name(KEY, Path(self.path).name)}"'
            )

        self.send_header('Content-Type', self.guess_type(path))
        self.send_header('Content-Length', str(file_size - start))
        self.add_default_headers()
        self.end_headers()

        try:
            with open(path, 'rb') as f:
                decrypt_stream(KEY,
                               BinaryIOBytesInStream(f),
                               BinaryIOBytesOutStream(self.wfile),
                               start,
                               update_last_access_time)
        except ConnectionError:
            pass

    def send_page(self):
        path = Path(self.translate_path(self.path))
        name = path.name
        directory = Directory(path.parent)

        prev_page = None
        next_page = None
        stop = False

        for file in directory.sorted_files():
            if os.path.isdir(directory.path.joinpath(file.relative_path)):
                continue
            elif stop:
                next_page = file.relative_path
                break
            elif file.relative_path == name:
                stop = True
            else:
                prev_page = file.relative_path

        resp = [f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>File</title>
        </head>
        <body>
            {LOGOUT_EL}
            <a id="{BACK}" style="margin-left: 5px" href=".">Back</a>
        ''']
        if prev_page:
            resp.append(f'<a id="{PREV}" style="margin-left: 5px" href="{prev_page}">Prev</a>')
        if next_page:
            resp.append(f'<a id="{NEXT}" style="margin-left: 5px" href="{next_page}">Next</a>')
        resp.append(f'<h2>Current file: {decrypt_path(KEY, self.path)}</h2>')

        fyle_type = self.guess_type(decrypt_name(KEY, name))[0]

        if fyle_type == 'v':
            resp.append(f'''
            <video style="max-width: 1200px; max-height: 720px" src="{name}" reload="auto" controls>
                <source src="{name}"/>
            </video>
            ''')
        elif fyle_type == 'i':
            resp.append(f'<img id="image" src="{name}"/>')
            resp.append(
                # language=HTML
                '''<script>
                let image = document.getElementById('image'),
                    flag = true;

                image.style['max-width'] = '1200px';
                image.style['max-height'] = '720px';
                image.onclick = () => {
                    if (flag) {
                        image.style['max-width'] = null;
                        image.style['max-height'] = null;
                    } else {
                        image.style['max-width'] = '1200px';
                        image.style['max-height'] = '720px';
                    }
                    flag = !flag;
                }
                </script>'''
            )
        else:
            resp.append('<pre>')

            buf = InMemoryBytesOutStream()
            with open(path, 'rb') as f:
                decrypt_stream(KEY, BinaryIOBytesInStream(f), buf)

            resp.append(buf.buf.decode(ENCODING).replace('<', '&lt;').replace('>', '&gt;'))
            resp.append('</pre>')

        resp.append(f'''
            {COMMON_SCRIPT}
        </body>
        </html>
        ''')

        self.send_text(resp)

    def send_login(self):
        # noinspection HtmlUnknownTarget
        # language=HTML
        self.send_text([f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <title>Login</title>
            </head>
            <body>
                <form method="POST" action="{LOGIN_PAGE}">
                    <input id="password" required name="{PASSWORD_PARAM}" placeholder="Password" type="password"/>
                    <input type="submit" value="Login"/>
                </form>
                <script>
                window.onload = () => {{
                    document.getElementById("password").focus();
                }}
                </script>
            </body>
            </html>
            '''])

    def process_login(self):
        global KEY

        password = self.get_form_data()['password']

        with open(KEY_PATH, 'ab+') as f:
            f.seek(0)
            key = f.read()
            if not key:
                key = Random.new().read(32)
                key = encrypt(password, key)
                f.write(key)

            KEY = decrypt(password, key)

        self.send_main_page()

    def send_change_password(self):
        # noinspection HtmlUnknownTarget
        # language=HTML
        self.send_text([f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <title>Login</title>
            </head>
            <body>
                <form method="POST" action="{CHANGE_PASSWORD_PAGE}">
                    <input required name="{PASSWORD_PARAM}" placeholder="Password" type="password"/>
                    <input required name="{AGAIN_PARAM}" placeholder="Again" type="password"/>
                    <input type="submit" value="Change"/>
                </form>
            </body>
            </html>
            '''])

    def process_change_password(self):
        form = self.get_form_data()
        password = form[PASSWORD_PARAM]
        again = form[AGAIN_PARAM]

        if password is None or password != again:
            self.send_reload()
            return

        backup = KEY_PATH + '_backup'

        i = 1
        while os.path.exists(backup):
            i += 1
            backup += str(i)

        os.rename(KEY_PATH, backup)

        try:
            with open(KEY_PATH, 'wb') as f:
                f.write(encrypt(password, KEY))
        except:
            if os.path.exists(KEY_PATH):
                os.remove(KEY_PATH)
            os.rename(backup, KEY_PATH)
            raise

        os.remove(backup)

        self.send_main_page()

    def process_save(self):
        form = cgi.FieldStorage(fp=self.rfile,
                                headers=self.headers,
                                environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']})

        files = form[FILE_PARAM]
        if not isinstance(files, list):
            files = [files]

        for record in files:
            with open(Path(self.translate_path(self.path)).parent.joinpath(encrypt_name(KEY, record.filename)),
                      'wb') as f_out:
                encrypt_stream(KEY, BinaryIOBytesInStream(record.file), BinaryIOBytesOutStream(f_out))
        self.send_preview_page()

    def process_not_encrypted(self):
        encrypt_content(KEY, self.translate_path(self.path.rsplit('/', 1)[0]))
        self.send_preview_page()

    def process_clear_temp(self):
        shutil.rmtree(TEMP_PATH)
        os.makedirs(TEMP_PATH, exist_ok=True)
        self.send_preview_page()

    def process_create(self):
        directory = self.get_form_data()[DIR_PARAM]
        directory = encrypt_name(KEY, directory)
        os.makedirs(Path(self.translate_path(self.path)).parent.joinpath(directory),
                    exist_ok=True)
        self.send_preview_page()

    def do_POST(self):
        global KEY

        try:
            validate_timeout()

            if self.path.endswith(LOGIN_PAGE):
                self.process_login()
                return

            if not KEY:
                self.send_redirect_login()
                return

            if self.path.endswith(SAVE_REQUEST):
                self.process_save()
                return

            if self.path.endswith(CREATE_REQUEST):
                self.process_create()
                return

            if self.path.endswith(CHANGE_PASSWORD_PAGE):
                self.process_change_password()
                return

            self.send_response(404)
        except ValueError as e:
            print(e)
            KEY = None
            self.send_redirect_login()

    def do_GET(self):
        global KEY

        try:
            validate_timeout()

            if self.path.endswith(FAVICON):
                self.send_text('')
                return

            if self.path.endswith(LOGOUT_PAGE):
                KEY = None

            if self.path.endswith(LOGIN_PAGE) or not KEY:
                self.send_login()
                return

            if self.path.endswith(PROCESS_NOT_ENCRYPTED_REQUEST):
                self.process_not_encrypted()
                return

            if self.path.endswith(CLEAR_TEMP_REQUEST):
                self.process_clear_temp()
                return

            if self.path.endswith(CHANGE_PASSWORD_PAGE):
                self.send_change_password()
                return

            path = self.translate_path(self.path)

            if not os.path.exists(path):
                self.send_response(404)
                return

            if os.path.isdir(path):
                self.send_directory()
                return

            accept = self.headers.get('Accept')
            if not accept or len([x for x in accept.split(',') if x.startswith('text')]) == 0:
                self.send_file()
                return

            self.send_page()
        except ValueError as e:
            print(e)
            KEY = None
            self.send_login()


if __name__ == '__main__':
    httpd = None
    try:
        if not os.path.exists(KEY_PATH) and os.path.exists(CONTENT_PATH) and len(os.listdir(CONTENT_PATH)) > 0:
            print(f'{KEY_PATH} doesnt exist. Cant open content without it.')
            exit(-1)

        os.makedirs(META_PATH, exist_ok=True)
        os.makedirs(CONTENT_PATH, exist_ok=True)

        httpd = ThreadedHTTPServer(('', PORT), CustomRequestHandler)
        print(f'Serving on port {PORT}')

        webbrowser.open(f'http://localhost:{PORT}', new=0, autoraise=True)

        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nServer terminated.')
        if httpd:
            httpd.server_close()
