import logging
import os

import pyzipper

logger = logging.getLogger(__name__)


def extract_files(zip_path, password, extract_to="extracted_files"):
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.pwd = password.encode()
        zf.extractall(extract_to)


def try_open_zip_without_password(zip_path):
    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            print(1)
            first_file = zf.namelist()[0]
            with zf.open(first_file) as file:
                file.read()
            print(2)
            return True
    except RuntimeError as e:
        if 'password' in str(e):
            logger.error("Password is required to open the zip file")
            return True
    except Exception as e:
        logger.error(f"An error occurred: {e}")


def try_open_zip_with_password(zip_path, password):
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
    try:
        with open(passwords_file_path, 'r') as file:
            for line in file:
                yield line.strip()
    except FileNotFoundError:
        logger.error("Passwords file not found")
        exit(1)


def brute_force_zip(zip_path, passwords_file_path):
    password_tries = 0
    logger.info("Starting brute force attack")
    for password in password_generator(passwords_file_path):
        password_tries += 1
        if try_open_zip_with_password(zip_path, password):
            logger.info(f"Password found: {password}")
            logger.info(f"Passwords tried: {password_tries}")
            return password
    logger.error("Password not found")


def create_zip_with_password(zip_file_path, files_directory_path, password, utility_file_paths):
    with pyzipper.AESZipFile(zip_file_path,
                             'w',
                             compression=pyzipper.ZIP_LZMA,
                             encryption=pyzipper.WZ_AES) as zf:
        logger.info("Creating a password-protected zip file")
        zf.setpassword(password.encode())
        logger.info(f"Adding files from directory: {files_directory_path} to zip file")
        for root, _, files in os.walk(files_directory_path):
            for file in files:
                logger.info(f"Adding file: {file} to zip file with arcname: {os.path.basename(file)}")
                zf.write(os.path.join(root, file), arcname=os.path.basename(file))

        logger.info(f"Adding utility files to zip file")
        for file in utility_file_paths:
            logger.info(f"Adding utility file: {file} to zip file with arcname: {os.path.basename(file)}")
            zf.write(file, arcname=os.path.join("utils", os.path.basename(file)))