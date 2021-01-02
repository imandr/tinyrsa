import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname), "r").read()

def get_version():
    g = {}
    exec(open(os.path.join("tinyrsa", "version.py"), "r").read(), g)
    return g["version"]


setup(
    name = "tinyrsa",
    version = get_version(),
    author = "Igor Mandrichenko",
    author_email = "igorvm@gmail.com",
    description = ("Minimalistic implementation of RSA-based public key encryption suite"),
    license = "BSD 3-clause",
    keywords = "security, encryption, RSA, public key encryption",
    url = "https://github.com/imandr/tinyrsa",
    packages=['tinyrsa', "tinyrsa.ui"],
    long_description=read('README.rst'),
    install_requires=["pycrypto"],
    zip_safe = False,
    classifiers=[
    ],
    entry_points = {
            "console_scripts": [
                "tinyrsa = tinyrsa.ui.rsa:main",
            ]
        }
)