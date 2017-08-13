import functools
import pkg_resources


@functools.lru_cache(maxsize=1)
def get_parsers():
    entry_points = pkg_resources.iter_entry_points('pnet.packet')
    return {entry_point.name: entry_point.load()
            for entry_point in entry_points}


def parse(name, data):
    return get_parsers()[name](data)
