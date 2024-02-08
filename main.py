import os
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

class CustomRequestHandler(SimpleHTTPRequestHandler):
    def list_directory(self, path):
        try:
            # Create a list of files and directories in the current path
            entries = os.listdir(path)

            # Begin the HTML page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # HTML page content
            self.wfile.write(b'<!DOCTYPE html>')
            self.wfile.write(b'<html><head><title>File List</title></head><body>')
            self.wfile.write(f'<h2>Current Directory: {path}</h2>'.encode('utf-8'))
            self.wfile.write(b'<ul>')

            for entry in entries:
                full_path = os.path.join(path, entry)
                if os.path.isdir(full_path):
                    entry += '/'
                self.wfile.write(f'<li><a href="{entry}">{entry}</a></li>'.encode('utf-8'))

            self.wfile.write(b'</ul></body></html>')

        except IOError:
            self.send_error(404, "Directory not found")

    def do_GET(self):
        # Get the absolute path of the requested file
        path = os.path.abspath(os.getcwd() + self.path)

        # If the path is a directory, list its contents
        if os.path.isdir(path):
            self.list_directory(path)
        else:
            # If the path is a file, serve it using the default handler
            super().do_GET()

if __name__ == "__main__":
    # Set the desired port (e.g., 8000)
    port = 8000

    # Start the server
    try:
        with TCPServer(("", port), CustomRequestHandler) as httpd:
            print(f"Serving on port {port}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer terminated.")
