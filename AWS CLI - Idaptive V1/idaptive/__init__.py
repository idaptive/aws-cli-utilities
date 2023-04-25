from importlib import metadata

try:
    __version__ = metadata.version("idaptive-aws-cli-utilities")
except ModuleNotFoundError:
    __version__ = "0.0.dev0"
