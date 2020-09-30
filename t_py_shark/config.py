import os

import py

import t_py_shark

CONFIG_PATH = os.path.join(os.path.dirname(t_py_shark.__file__), 'config.ini')

def get_config():
    return py.iniconfig.IniConfig(CONFIG_PATH)
