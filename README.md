About
=====

A simple YAFFS file system parser and extractor, written in Python.

Features
========

* List and/or extract regular files, folders, symlinks, hard links, and special device files
* Automatic detection and/or brute force of YAFFS build parameters (page size, spare size, endianess, etc)
* Support for both big and little endian YAFFS file systems
* Compatible with both Python2 and Python3

Installation
============

Use the included `setup.py` script to install:

```bash
$ python setup.py install
```

There are no required pre-requisites, besides Python itself.
