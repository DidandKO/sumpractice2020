import sys


class UnsupportedVersionException(Exception):
    pass


if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 5):
    raise UnsupportedVersionException("Your version of Python is unsupported. "
                                      "Pyshark requires Python >= 3.5 & Wireshark >= 2.2.0. "
                                      " Please upgrade or use t_py_shark-legacy, or t_py_shark version 0.3.8")

from t_py_shark.capture.live_capture import LiveCapture
from t_py_shark.capture.live_ring_capture import LiveRingCapture
from t_py_shark.capture.file_capture import FileCapture
from t_py_shark.capture.remote_capture import RemoteCapture
from t_py_shark.capture.inmem_capture import InMemCapture
