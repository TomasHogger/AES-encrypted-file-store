import cgi
import collections.abc
import datetime
import os
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Optional
from urllib import parse
import webbrowser
from Crypto import Random

from constants import MAX_INACTIVE_TIME, PORT, CONTENT_PATH, META_PATH, KEY_PATH, ENCRYPTED_FILE_PREFIX
from encrypter import ENCODING, decrypt_path, decrypt, decrypt_stream, BinaryIOBytesInStream, BinaryIOBytesOutStream, \
    InMemoryBytesOutStream, encrypt, encrypt_name, decrypt_name, convert_size_of_encrypted_to_real_size, encrypt_stream, \
    encrypt_content

LAST_ACCESS_TIME = datetime.datetime.fromtimestamp(1)
KEY: Optional[bytes] = None

LOGIN_PAGE = '/login'
LOGOUT_PAGE = '/logout'
CHANGE_PASSWORD_PAGE = '/change_password'
LOGOUT_EL = f'<a href="{LOGOUT_PAGE}">Logout</a>'
SAVE_REQUEST = '/save'
PROCESS_NOT_ENCRYPTED_REQUEST = '/process_not_encrypted'
FAVICON = 'favicon.ico'


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


def validate_timeout():
    global KEY, LAST_ACCESS_TIME
    if (datetime.datetime.now() - LAST_ACCESS_TIME).seconds >= MAX_INACTIVE_TIME:
        KEY = None
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
        resp = [f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>File List</title>
        </head>
        <body>
            {LOGOUT_EL}
            {'' if self.path == '/' else '<a style="margin-left: 5px" href="..">Back</a>'}
            <a href="{PROCESS_NOT_ENCRYPTED_REQUEST}" style="margin-left: 5px">Process not encrypted</a>
            <a href="{CHANGE_PASSWORD_PAGE}" style="margin-left: 5px">Change password</a>
            <br/>
            <h2>Current Directory: {decrypt_path(KEY, self.path)}</h2>
            
            <form method='POST' action='save' enctype=multipart/form-data>
                <input required name='file' type='file' multiple/>
                <input type='submit' value='Add'/>
            </form>
            <br/>
        ''']

        path = self.translate_path(self.path)

        dirs = []
        files = []
        not_encrypted = []
        for entry in os.listdir(self.translate_path(self.path)):
            if not entry.startswith(ENCRYPTED_FILE_PREFIX):
                not_encrypted.append(entry)
                continue

            name = decrypt_name(KEY, entry)
            if os.path.isdir(os.path.join(path, entry)):
                dirs.append([entry, name])
            else:
                files.append([entry, name])

        for e in dirs:
            resp.append(f'<li><a href="{e[0]}/">[Dir] {e[1]}</a></li>')
        for e in files:
            resp.append(f'<li><a href="{e[0]}">{e[1]}</a></li>')
        for e in not_encrypted:
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
                decrypt_stream(KEY, BinaryIOBytesInStream(f), BinaryIOBytesOutStream(self.wfile), start)
        except ConnectionError:
            pass

    def send_page(self):
        path = Path(self.translate_path(self.path))
        name = path.name
        directory = path.parent

        prev_page = None
        next_page = None
        stop = False
        for file in os.listdir(directory):
            if os.path.isdir(directory.joinpath(file)):
                continue
            elif stop:
                next_page = file
                break
            elif file == name:
                stop = True
            else:
                prev_page = file

        resp = [f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>File</title>
        </head>
        <body>
            {LOGOUT_EL}
            <a style="margin-left: 5px" href=".">Back</a>
        ''']
        if prev_page:
            resp.append(f'<a style="margin-left: 5px" href="{prev_page}">Prev</a>')
        if next_page:
            resp.append(f'<a style="margin-left: 5px" href="{next_page}">Next</a>')
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
                '''
                <script>
                    let image = document.getElementById('image'),
                        flag = true
                        
                    image.style['max-width'] = '1200px'
                    image.style['max-height'] = '720px'
                    image.onclick = () => {
                        if (flag) {
                            image.style['max-width'] = null
                            image.style['max-height'] = null
                        } else {
                            image.style['max-width'] = '1200px'
                            image.style['max-height'] = '720px'
                        }
                        flag = !flag
                    }
                </script>
                '''
            )
        else:
            resp.append('<pre>')

            buf = InMemoryBytesOutStream()
            with open(path, 'rb') as f:
                decrypt_stream(KEY, BinaryIOBytesInStream(f), buf)

            resp.append(buf.buf.decode(ENCODING).replace('<', '&lt;').replace('>', '&gt;'))
            resp.append('</pre>')

        resp.append('''
        </body>
        </html>
        ''')

        self.send_text(resp)

    def send_login(self):
        self.send_text([f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login</title>
            </head>
            <body>
                <form method='POST' action='{LOGIN_PAGE}'>
                    <input required name='password' placeholder="Password" type='password'/>
                    <input type="submit" value="Login"/>
                </form>
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
        self.send_text([f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login</title>
            </head>
            <body>
                <form method='POST' action='{CHANGE_PASSWORD_PAGE}'>
                    <input required name='password' placeholder="Password" type='password'/>
                    <input required name='again' placeholder="Again" type='password'/>
                    <input type="submit" value="Change"/>
                </form>
            </body>
            </html>
            '''])

    def process_change_password(self):
        form = self.get_form_data()
        password = form['password']
        again = form['again']

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
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']})

        files = form['file']
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
        if not os.path.exists(KEY_PATH) \
                and os.path.exists(CONTENT_PATH) \
                and len(os.listdir(CONTENT_PATH)) > 0:
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
