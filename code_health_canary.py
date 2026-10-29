"""Static-only negative fixture for the unmerged CI enforcement experiment."""


def deliberately_unsafe(value):
    return eval(value)
