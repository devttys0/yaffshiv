#!/usr/bin/env python
import os
from distutils.core import setup, Command
from distutils.dir_util import remove_tree

SCRIPT_NAME = "yaffshiv"

class CleanCommand(Command):
    description = "Clean Python build directories"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            remove_tree("build")
        except KeyboardInterrupt as e:
            raise e
        except Exception:
            pass

        try:
            remove_tree("dist")
        except KeyboardInterrupt as e:
            raise e
        except Exception:
            pass

setup(name = SCRIPT_NAME,
      version = "0.1",
      description = "YAFFS extraction tool",
      author = "Craig Heffner",
      url = "https://github.com/devttys0/%s" % SCRIPT_NAME,
      requires = [],
      scripts = [os.path.join("src", SCRIPT_NAME)],
      cmdclass = {'clean' : CleanCommand}
)

