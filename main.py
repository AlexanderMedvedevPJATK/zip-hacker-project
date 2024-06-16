import logging
import os

import modules.files_handler as fh
from modules.logger import setup_logging
from modules.virus_total_handler import verify_checksum
import modules.archive_handler as ah
import modules.raport_generator as rg

logger = logging.getLogger(__name__)
zipfile_path = input("Enter the path to the zip file: ")
search_for = ["PESEL", "password"]
extract_to_path = "extracted_files"
passwords_file_path = "10k-most-common.txt"
logs_file_path = "logs.log"
report_file_path = "report.txt"
report_checksum_path = "report_checksum.txt"
new_zipfile_path = "report.zip" if zipfile_path != "report.zip" else "report2.zip"
new_password = "P4$$w0rd!"

if not os.path.exists(zipfile_path) or not zipfile_path.endswith(".zip"):
    logger.error("Invalid zip file path")
    exit(1)


def main():
    setup_logging(logs_file_path)

    is_protected = ah.try_open_zip_without_password(zipfile_path)
    correct_password = ""
    if is_protected:
        correct_password = ah.brute_force_zip(zipfile_path, passwords_file_path)
        if correct_password is None:
            logger.error("Exiting the program")
            return

    ah.extract_files(zipfile_path, correct_password)
    binary_files_content = fh.get_files_binary_content_in_directory(extract_to_path)

    file_checksum = {}
    file_keywords = {}
    file_emails = {}
    file_virus_total_response = {}

    for filename, content in binary_files_content.items():
        checksum = fh.generate_sha256_checksum(filename, content)
        file_checksum[os.path.basename(filename)] = checksum

        virus_total_response = verify_checksum(checksum)
        file_virus_total_response[os.path.basename(filename)] = virus_total_response

        if filename.endswith((".txt", ".pdf", ".docx", ".doc")):
            decoded_content = fh.decode_content(filename, content)

            keyword_occurrences = fh.look_for_keywords(filename, decoded_content, search_for)
            file_keywords[os.path.basename(filename)] = keyword_occurrences

            emails = set(fh.look_for_emails(filename, decoded_content))
            file_emails[os.path.basename(filename)] = emails

    generated_report = rg.generate_report(file_checksum, file_keywords, file_emails, file_virus_total_response)
    rg.write_report_to_file(generated_report, report_file_path)

    report_binary_content = fh.get_file_binary_content(report_file_path)

    report_checksum = fh.generate_sha256_checksum(report_file_path, report_binary_content)

    fh.create_and_write_to_file(report_checksum_path, report_checksum)
    logger.info(f"Report checksum saved to: {report_checksum_path}")

    ah.create_zip_with_password(
        new_zipfile_path,
        extract_to_path,
        new_password,
        [report_file_path, report_checksum_path, logs_file_path]
    )

    fh.remove_directory(extract_to_path)


if __name__ == "__main__":
    main()

