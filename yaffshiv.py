#!/usr/bin/env python

import os
import sys
import struct

class YAFFSConfig(object):

    def __init__(self, **kwargs):
        for (k, v) in kwargs.iteritems():
            setattr(self, k, v)

class YAFFS(object):
    BIG_ENDIAN = ">"
    LITTLE_ENDIAN = "<"

    # These assume non-unicode YAFFS name lengths
    YAFFS_MAX_NAME_LENGTH       = 255 - 2 # NOTE: This is from observation; YAFFS code says 255.
    YAFFS_MAX_ALIAS_LENGTH      = 159

    YAFFS_OBJECT_TYPE_UNKNOWN   = 0
    YAFFS_OBJECT_TYPE_FILE      = 1
    YAFFS_OBJECT_TYPE_SYMLINK   = 2
    YAFFS_OBJECT_TYPE_DIRECTORY = 3
    YAFFS_OBJECT_TYPE_HARDLINK  = 4
    YAFFS_OBJECT_TYPE_SPECIAL   = 5

    DEFAULT_PAGE_SIZE           = 0x1000
    DEFAULT_SPARE_SIZE          = 0x10

    data = b''
    offset = 0
    config = None

    def read_long(self):
        return struct.unpack("%sL" % self.config.endianess, self.data[self.offset:self.offset+4])[0]

    def read_short(self):
        return struct.unpack("%sH" % self.config.endianess, self.data[self.offset:self.offset+2])[0]

    def read_next(self, size, raw=False):
        if size == 4 and not raw:
            val = self.read_long()
        elif size == 2 and not raw:
            val = self.read_short()
        else:
            val = self.data[self.offset:self.offset+size]

        self.offset += size
        return val

    def read_page(self):
        data = self.read_next(self.config.page_size)
        spare = self.read_next(self.config.spare_size)
        return (data, spare)

    def null_terminate_string(self, string):
        try:
            i = string.index(b'\x00')
        except Exception as e:
            i = len(string)

        return string[0:i]

class YAFFSObjType(YAFFS):

    TYPE2STR = {
                YAFFS.YAFFS_OBJECT_TYPE_UNKNOWN   : "YAFFS_OBJECT_TYPE_UNKNOWN",
                YAFFS.YAFFS_OBJECT_TYPE_FILE      : "YAFFS_OBJECT_TYPE_FILE",
                YAFFS.YAFFS_OBJECT_TYPE_SYMLINK   : "YAFFS_OBJECT_TYPE_SYMLINK",
                YAFFS.YAFFS_OBJECT_TYPE_DIRECTORY : "YAFFS_OBJECT_TYPE_DIRECTORY",
                YAFFS.YAFFS_OBJECT_TYPE_HARDLINK  : "YAFFS_OBJECT_TYPE_HARDLINK",
                YAFFS.YAFFS_OBJECT_TYPE_SPECIAL   : "YAFFS_OBJECT_TYPE_SPECIAL",
               }

    def __init__(self, data, config):
        self.data = data
        self.config = config
        self._type = self.read_long()
        self.offset = self.offset

    def __str__(self):
        return self.TYPE2STR[self._type]

    def __int__(self):
        return self._type

    def __get__(self, instance, owner):
        return self._type

class YAFFSSpare(YAFFS):

    def __init__(self, data, config):
        self.data = data
        self.config = config

        # YAFFS images built without --yaffs-ecclayout have an extra two
        # bytes before the chunk ID. Possibly an unused CRC? Always 0xFFFF (?).
        if not self.config.ecclayout or (self.config.auto_detect and self.read_short() == 0xFFFF):
            junk = self.read_next(2)

        self.chunk_id = self.read_next(4)
        self.obj_id = self.read_next(4)

class YAFFSEntry(YAFFS):

    def __init__(self, data, spare, config):
        self.data = data
        self.config = config
        self.file_data = b''

        obj_type_raw = self.read_next(4, raw=True)
        self.yaffs_obj_type = YAFFSObjType(obj_type_raw, self.config)

        self.parent_obj_id = self.read_next(4)

        self.sum_no_longer_used = self.read_next(2)
        self.name = self.null_terminate_string(self.read_next(self.YAFFS_MAX_NAME_LENGTH+1))

        # Should be 0xFFFFFFFF
        junk = self.read_next(4)

        self.yst_mode = self.read_next(4)
        self.yst_uid = self.read_next(4)
        self.yst_gid = self.read_next(4)
        self.yst_atime = self.read_next(4)
        self.yst_mtime = self.read_next(4)
        self.yst_ctime = self.read_next(4)
        self.file_size_low = self.read_next(4)
        self.equiv_id = self.read_next(4)

        # Aliases are for symlinks only
        self.alias = self.null_terminate_string(self.read_next(self.YAFFS_MAX_ALIAS_LENGTH+1))

        # stuff for block and char devices (major/min)
        self.yst_rdev = self.read_next(4)

        # Appears to be for WinCE
        self.win_ctime_1 = self.read_next(4)
        self.win_ctime_2 = self.read_next(4)
        self.win_atime_1 = self.read_next(4)
        self.win_atime_2 = self.read_next(4)
        self.win_mtime_1 = self.read_next(4)
        self.win_mtime_2 = self.read_next(4)

        self.inband_shadowed_obj_id = self.read_next(4)
        self.inband_is_shrink = self.read_next(4)
        self.file_size_high = self.read_next(4)
        self.reserved = self.read_next(1)

        self.shadows_obj = self.read_next(4)
        self.is_shrink = self.read_next(4)

        # Calculate file size
        if self.file_size_high != 0xFFFFFFFF:
            self.file_size = self.file_size_low | (self.file_size_high << 32)
        elif self.file_size_low != 0xFFFFFFFF:
            self.file_size = self.file_size_low
        else:
            self.file_size = 0

        self.spare = YAFFSSpare(spare, self.config)
        self.yaffs_obj_id = self.spare.obj_id

class YAFFSParser(YAFFS):

    def __init__(self, data, config):
        self.data = data
        self.data_len = len(data)
        self.config = config

    def __enter__(self):
        return self

    def __exit__(self, a, b, c):
        return None

    def next_entry(self):
        while self.offset < self.data_len:
            # Read and parse the object header data
            (obj_hdr_data, obj_hdr_spare) = self.read_page()
            obj_hdr = YAFFSEntry(obj_hdr_data, obj_hdr_spare, self.config)

            # Read in the file data, one page at a time
            if obj_hdr.file_size > 0:
                bytes_remaining = obj_hdr.file_size

                while bytes_remaining:
                    (data, spare) = self.read_page()
                    if len(data) < bytes_remaining:
                        obj_hdr.file_data += data
                        bytes_remaining -= len(data)
                    else:
                        obj_hdr.file_data += data[0:bytes_remaining]
                        bytes_remaining = 0

            yield obj_hdr

class YAFFSExtractor(YAFFS):

    def __init__(self, data, config):
        self.file_paths = {}
        self.file_entries = {}
        self.data = data
        self.config = config

    def parse(self):
        with YAFFSParser(self.data, self.config) as parser:
            for entry in parser.next_entry():
                if self.file_paths.has_key(entry.parent_obj_id):
                    path = os.path.join(self.file_paths[entry.parent_obj_id], entry.name)
                else:
                    path = entry.name

                self.file_paths[entry.yaffs_obj_id] = path
                self.file_entries[entry.yaffs_obj_id] = entry

                if self.config.debug:
                    self._print_entry(entry)

        return len(self.file_entries)

    def _print_entry(self, entry):
        sys.stdout.write("###################################################\n")
        sys.stdout.write("File type: %s\n" % str(entry.yaffs_obj_type))
        sys.stdout.write("File ID: %d\n" % entry.yaffs_obj_id)
        sys.stdout.write("File parent ID: %d\n" % entry.parent_obj_id)
        sys.stdout.write("File name: %s" % self.file_paths[entry.yaffs_obj_id])
        if int(entry.yaffs_obj_type) == self.YAFFS_OBJECT_TYPE_SYMLINK:
            sys.stdout.write(" -> %s\n" % entry.alias)
        else:
            sys.stdout.write("\n")
        sys.stdout.write("File size: 0x%X\n" % entry.file_size)
        sys.stdout.write("File mode: %d\n" % entry.yst_mode)
        sys.stdout.write("File UID: %d\n" % entry.yst_uid)
        sys.stdout.write("File GID: %d\n" % entry.yst_gid)
        #sys.stdout.write("First bytes: %s\n" % entry.file_data[0:16])
        sys.stdout.write("###################################################\n\n")


    def ls(self):
        for (entry_id, entry) in self.file_entries.iteritems():
            self._print_entry(entry)

    def set_mode_owner(self, file_path, entry):
        if self.config.preserve_mode:
            os.chmod(file_path, entry.yst_mode)
        if self.config.preserve_owner:
            os.chown(file_path, entry.yst_uid, entry.yst_gid)

    def extract(self, outdir):
        dir_count = 0
        file_count = 0
        symlink_count = 0

        # Create directories
        for (entry_id, file_path) in self.file_paths.iteritems():
            entry = self.file_entries[entry_id]
            if file_path and int(entry.yaffs_obj_type) == self.YAFFS_OBJECT_TYPE_DIRECTORY:
                try:
                    file_path = os.path.join(outdir, file_path)
                    os.makedirs(file_path)
                    self.set_mode_owner(file_path, entry)
                    dir_count += 1
                except Exception as e:
                    sys.stderr.write("WARNING: Failed to create directory '%s': %s\n" % (file_path, str(e)))

        # Create files
        for (entry_id, file_path) in self.file_paths.iteritems():
            if file_path:
                file_path = os.path.join(outdir, file_path)
                entry = self.file_entries[entry_id]
                if int(entry.yaffs_obj_type) == self.YAFFS_OBJECT_TYPE_FILE:
                    try:
                        with open(file_path, 'wb') as fp:
                            fp.write(self.file_entries[entry_id].file_data)
                        self.set_mode_owner(file_path, entry)
                        file_count += 1
                    except Exception as e:
                        sys.stderr.write("WARNING: Failed to create file '%s': %s\n" % (file_path, str(e)))

        # Create symlinks
        for (entry_id, file_path) in self.file_paths.iteritems():
            entry = self.file_entries[entry_id]
            if file_path and int(entry.yaffs_obj_type) == self.YAFFS_OBJECT_TYPE_SYMLINK:
                dst = os.path.join(outdir, file_path)
                src = entry.alias
                try:
                    os.symlink(src, dst)
                    symlink_count += 1
                except Exception as e:
                    sys.stderr.write("WARNING: Failed to create symlink '%s' -> '%s': %s\n" % (dst, src, str(e)))

        return (dir_count, file_count, symlink_count)

if __name__ == "__main__":

    try:
        page_size = int(sys.argv[1])
        spare_size = int(sys.argv[2])
        in_file = sys.argv[3]
        out_dir = sys.argv[4]
    except Exception as e:
        sys.stdout.write("Usage: %s <page_size> <spare_size> <yaffs image> <output directory>\n" % sys.argv[0])
        sys.exit(1)

    try:
        with open(in_file, 'rb') as fp:
            data = fp.read()
    except Exception as e:
        sys.stderr.write("Failed to open file '%s': %s\n" % (in_file, str(e)))
        sys.exit(1)

    try:
        os.makedirs(out_dir)
    except Exception as e:
        sys.stderr.write("Failed to create output directory: %s\n" % str(e))
        sys.exit(1)

    config = YAFFSConfig(endianess=YAFFS.LITTLE_ENDIAN,
                         page_size=page_size,
                         spare_size=spare_size,
                         ecclayout=True,
                         auto_detect=True,
                         preserve_mode=True,
                         preserve_owner=False,
                         debug=True)


    fs = YAFFSExtractor(data, config)
    sys.stdout.write("Parsing YAFFS objects...\n")
    obj_count = fs.parse()
    sys.stdout.write("Parsed %d objects\n" % obj_count)

    (dc, fc, sc) = fs.extract(out_dir)
    sys.stdout.write("Created %d directories, %d files, and %d symlinks.\n" % (dc, fc, sc))

