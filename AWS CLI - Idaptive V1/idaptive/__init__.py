import sys

if sys.version_info >= (3, 8):
    from importlib import metadata
else:
    import importlib_metadata as metadata

try:
    __version__ = metadata.version("idaptive-aws-cli-utilities")
except ModuleNotFoundError:
    __version__ = "0.0.dev0"
