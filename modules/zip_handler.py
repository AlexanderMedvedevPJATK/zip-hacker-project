import logging

import pyzipper

logger = logging.getLogger(__name__)


def extract_files(zip_path, password):
    files_content = {}
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.pwd = password.encode()
        for filename in zf.namelist():
            with zf.open(filename) as file:
                logger.info(f"Reading file: {filename}")
                content = bytearray()
                for chunk in iter(lambda: file.read(4096), b""):
                    content.extend(chunk)
                files_content[file.name] = bytes(content)
    return files_content


def try_open_zip(zip_path, password):
    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            logger.info(f"Trying password: {password}")
            zf.pwd = password.encode()
            first_file = zf.namelist()[0]
            with zf.open(first_file) as file:
                file.read()
            return True
    except RuntimeError as e:
        if 'Bad password for file' in str(e):
            logger.error(f"Password {password} is incorrect")
            return False
    except Exception as e:
        logger.error(f"An error occurred: {e}")


def password_generator(passwords_file_path):
    with open(passwords_file_path, 'r') as file:
        for line in file:
            yield line.strip()


def brute_force_zip(zip_path, passwords_file_path):
    for password in password_generator(passwords_file_path):
        if try_open_zip(zip_path, password):
            logger.info(f"Password found: {password}")
            return password
