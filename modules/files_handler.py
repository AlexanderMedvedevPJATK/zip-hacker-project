import hashlib
import logging
import os
import re

from docx import Document

logger = logging.getLogger(__name__)


def get_file_binary_content(file_path):
    content = bytearray()
    with open(file_path, "rb") as file:
        logger.info(f"Reading file: {os.path.basename(file_path)} in binary mode")
        for chunk in iter(lambda: file.read(4096), b""):
            content.extend(chunk)
    return bytes(content)


def get_files_binary_content_in_directory(directory_path):
    binary_files_content = {}
    for root, _, files in os.walk(directory_path):
        for file in files:
            binary_content = get_file_binary_content(os.path.join(root, file))
            binary_files_content[os.path.join(root, file)] = binary_content
    return binary_files_content


def generate_sha256_checksum(filename, binary_content):
    logger.info(f"Generating checksum for file: {filename}")
    sha256_hash = hashlib.sha256()
    sha256_hash.update(binary_content)
    checksum = sha256_hash.hexdigest()
    logger.info(f"Checksum for file: {filename} is {checksum}")
    return checksum


def look_for_keywords(filename, decoded_content, keywords):
    keywords_occurrences = {}
    decoded_content = decoded_content.lower()
    for keyword in keywords:
        keyword = keyword.lower()
        if keyword in decoded_content:
            logger.info(f"Found keyword: {keyword} in file: {filename}")
            keywords_occurrences[keyword] = decoded_content.count(keyword)

    return keywords_occurrences


def look_for_emails(filename, decoded_content):
    email_pattern = r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    emails = re.findall(email_pattern, decoded_content)
    if emails:
        logger.info(f"Found emails in file: {filename}: {emails}")

    return emails


def decode_content(filename, binary_content):
    logger.info(f"Decoding binary content of file: {filename}")
    if filename.endswith('.docx'):
        document = Document(filename)
        decoded_content = ' '.join([paragraph.text for paragraph in document.paragraphs])
    else:
        decoded_content = binary_content.decode()

    return decoded_content


def create_and_write_to_file(filename, content):
    logger.info(f"Creating file: {filename}")
    with open(filename, 'w') as file:
        file.write(content)