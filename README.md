# Application for storing files encrypted with AES.

## Goal

Some files need to be stored in an encrypted format. While ZIP is convenient for this purpose, it has some drawbacks:

- It may be difficult to sync a large encrypted ZIP file with another storage.
- When a file is opened from a ZIP, the ZIP decrypts the entire file, saves it in the cache on disk, and then passes it
  to the default app for the file extension.
- It takes more and more time to add a file to an existing ZIP with a large size.

To address these issues, I have created this web-based application. It stores files encrypted with chunks and allows
users to access them through a browser, eliminating the need for dealing with large ZIP files.

## Some info

- **WARNING!** This app is not safe for public use; it is intended for personal use on the computer where you run it.
  **DO NOT** open the app's port to the local or public network!
- **WARNING! DO NOT** delete the `Meta/key` file; it's the main key of the app. If you lose it, you cannot decrypt
  files!
- The application starts on port 8000.
- All magic constants are stored in `constants.py`.
- Run `main.py` from the project directory.
- All files are stored in the `Content` folder.
- On the first run, the application will prompt you to set a password. You will use this password to log in on
  subsequent times.

## Usage

```
pip install -r requirements.txt
python main.py
```
