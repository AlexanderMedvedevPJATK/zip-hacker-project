def generate_report(file_checksum, file_keywords, file_emails, file_virus_total_response):
    max_filename_length = max([len(filename) for filename in file_checksum.keys()])
    max_keyword_length = max([len(keyword) for keywords in file_keywords.values() for keyword in keywords.keys()])
    checksum_length = 64
    text_file_list_set = set(file_keywords.keys() & file_emails.keys())

    report = f"{'=' * 20} REPORT {'=' * 20}\n\n"
    report += f"{'Filename':<{max_filename_length + 5}}"
    report += f"{'Checksum':<{checksum_length + 5}}"
    report += "VirusTotal response:\n"
    for filename, checksum in file_checksum.items():
        report += (f"{filename:<{max_filename_length + 5}}"
                   f"{checksum:<{checksum_length + 5}}"
                   f"{file_virus_total_response[filename]}\n")

    report += "\n==== Keywords and emails found in text files ====\n\n"

    for filename in text_file_list_set:
        report += "-" * 50 + "\n"
        report += f"{filename}\n"
        if file_keywords[filename]:
            report += (f"{'Keyword':<{max_keyword_length + 10}}"
                       f"Occurrence\n")
            for keyword, occurrences in file_keywords[filename].items():
                report += (f"{keyword:<{max_keyword_length + 10}}"
                           f"{occurrences}\n")

        if file_emails[filename]:
            report += "\nEmails found\n"
            for email in file_emails[filename]:
                report += f"{email}\n"

    return report


def write_report_to_file(report, filename):
    with open(filename, 'w') as file:
        file.write(report)
