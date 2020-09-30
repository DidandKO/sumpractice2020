"""Module used for the actual running of TShark"""
from distutils.version import LooseVersion
import os
import subprocess
import sys
import re
from sumpractice.settings import BASE_DIR

from t_py_shark.config import get_config


class TSharkNotFoundException(Exception):
    pass


class TSharkVersionException(Exception):
    pass


def get_process_path(tshark_path=None, process_name="tshark"):
    """Finds the path of the tshark executable.

    If the user has provided a path
    or specified a location in config.ini it will be used. Otherwise default
    locations will be searched.

    :param tshark_path: Path of the tshark binary
    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    pp = os.path.join(BASE_DIR, 't_py_shark/Wireshark/tshark.exe')
    return pp


def get_tshark_version(tshark_path=None):
    parameters = [get_process_path(tshark_path), "-v"]
    with open(os.devnull, "w") as null:
        version_output = subprocess.check_output(parameters, stderr=null).decode("ascii")

    version_line = version_output.splitlines()[0]
    pattern = '.*\s(\d+\.\d+\.\d+).*'  # match " #.#.#" version pattern
    m = re.match(pattern, version_line)
    if not m:
        raise TSharkVersionException("Unable to parse TShark version from: {}".format(version_line))
    version_string = m.groups()[0]  # Use first match found

    return LooseVersion(version_string)


def tshark_supports_duplicate_keys(tshark_version):
    return tshark_version >= LooseVersion("2.6.7")


def tshark_supports_json(tshark_version):
    return tshark_version >= LooseVersion("2.2.0")


def get_tshark_display_filter_flag(tshark_version):
    """Returns '-Y' for tshark versions >= 1.10.0 and '-R' for older versions."""
    if tshark_version >= LooseVersion("1.10.0"):
        return "-Y"
    else:
        return "-R"


def get_tshark_interfaces(tshark_path=None):
    """Returns a list of interface numbers from the output tshark -D.

    Used internally to capture on multiple interfaces.
    """
    parameters = [get_process_path(tshark_path), "-D"]
    with open(os.devnull, "w") as null:
        tshark_interfaces = subprocess.check_output(parameters, stderr=null).decode("utf-8")

    return [line.split(".")[0] for line in tshark_interfaces.splitlines()]
