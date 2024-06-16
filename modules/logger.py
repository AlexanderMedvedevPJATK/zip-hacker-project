import logging


def setup_logging(logs_file_path):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)-20s - %(name)-27s - %(levelname)-7s - %(message)s",
                        handlers=[
                            logging.StreamHandler(),
                            logging.FileHandler(logs_file_path)
                        ])
    logging.info('Logger initialized')
