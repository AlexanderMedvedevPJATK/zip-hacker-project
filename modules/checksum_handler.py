import hashlib
import logging

logger = logging.getLogger(__name__)


def generate_sha256_checksum(file_content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()
