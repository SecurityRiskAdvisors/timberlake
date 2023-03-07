import pathlib
from yaml import safe_load
import desert
import string
import random
import datetime
import urllib.request
from functools import lru_cache

from .types import List, Optional, Any


class FileLoaderMixin:
    """
    add a "from_file" class method to a class to allow instantiation from a yaml file
    on disk
    the path to the original file is set on the class instance as a propert prior to deserialization
    """

    def __init__(self):
        self.original_file_path = None

    @classmethod
    def from_file(cls, path: str):
        path = pathlib.Path(path)
        setattr(cls, "original_file_path", path.resolve())
        data = safe_load(path.read_text())
        return desert.schema(cls).load(data)


# https://stackoverflow.com/a/50173148
def deep_get(d: dict, keys: List) -> Optional[Any]:
    """safely get a nested value from a dict if it exists"""
    if not keys or d is None:
        return d
    return deep_get(d.get(keys[0]), keys[1:])


def epoch_now_ms() -> float:
    """get current UTC epoch time with milliseconds"""
    epoch = int(datetime.datetime.utcnow().strftime("%s")) * 1000
    return float(epoch)


def local_time_str() -> str:
    """get current local time in readable format"""
    return datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")


def zulu_time_str() -> str:
    """get current UTC Zulu time in readable format"""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")


@lru_cache(maxsize=None)
def get_public_ip() -> str:
    """get public IP address by quering Amazon"""
    # TODO: need to explicitly handle corp proxies?
    r = urllib.request.urlopen("https://checkip.amazonaws.com/", timeout=3)
    ip = r.read()
    return ip.decode()


def gen_rand_string(length: int) -> str:
    """generate a random string using digits and lowercase letters"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
