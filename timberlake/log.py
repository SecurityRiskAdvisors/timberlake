import logging

from .settings import global_settings

# suppress logging from boto library
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)


logging.basicConfig(
    filename=global_settings.log_file,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    filemode="w",
)
logger = logging.getLogger("timberlake")


def print_and_log(msg, msg_type="info"):
    fn = getattr(logger, msg_type)
    fn(msg)
    print(msg)
