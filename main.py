import logging

from modules.checksum_handler import generate_sha256_checksum
from modules.logger import setup_logging
from modules.zip_handler import brute_force_zip
from modules.zip_handler import extract_files

logger = logging.getLogger(__name__)


def main():
    setup_logging()
    correct_password = brute_force_zip("zipfile.zip", "10k-most-common.txt")
    binary_files_content = extract_files("zipfile.zip", correct_password)
    for filename, content in binary_files_content.items():
        logger.info(f"Generating checksum for file: {filename}")
        checksum = generate_sha256_checksum(content)
        logger.info(f"Checksum for file: {filename} is {checksum}")


if __name__ == "__main__":
    main()
