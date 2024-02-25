import re
from typing import Callable


def map_path(path: str, mapper: Callable[[str], str]) -> str:
    split_path = re.split(r'[\\/]+', path)
    flag = path.startswith('/')
    if flag:
        split_path = split_path[1:]
    split_path = [mapper(x) for x in split_path if x]
    path = '/'.join(split_path)
    if flag:
        path = '/' + path
    return path
