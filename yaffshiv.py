#!/usr/bin/env python

import os
import sys
import struct

class Compat(object):
    '''
    Python2/3 compatability methods.
    '''

    @staticmethod
    def str2bytes(s):
        if isinstance(s, str):
            return s.encode('latin-1')
        else:
            return s

    @staticmethod
    def iterator(d):
        if sys.version_info[0] > 2:
            return d.items()
        else:
            return d.iteritems()

    @staticmethod
    def has_key(d, k):
        if sys.version_info[0] > 2:
            return k in d
        else:
            return d.has_key(k)

class YAFFSConfig(object):
    '''
    Container class for storing global configuration data.
    '''

    SPARE_START_BIG_ENDIAN_ECC = b"\x00\x00\x10\x00"
    SPARE_START_BIG_ENDIAN_NO_ECC = b"\xFF\xFF\x00\x00\x10\x00"
    SPARE_START_LITTLE_ENDIAN_ECC = b"\x00\x10\x00\x00"
    SPARE_START_LITTLE_ENDIAN_NO_ECC = b"\xFF\xFF\x00\x10\x00\x00"

    def __init__(self, **kwargs):
        self.endianess = YAFFS.LITTLE_ENDIAN
        self.page_size = YAFFS.DEFAULT_PAGE_SIZE
        self.spare_size = YAFFS.DEFAULT_SPARE_SIZE
        self.ecclayout = True
        self.preserve_mode = True
        self.preserve_owner = False
        self.debug = True

        for (k, v) in Compat.iterator(kwargs):
            setattr(self, k, v)

        if hasattr(self, 'auto') and hasattr(self, 'sample_data'):
            self._auto_detect_settings()
            if self.debug:
                sys.stdout.write("Page size: %d\n" % self.page_size)
                sys.stdout.write("Spare size: %d\n" % self.spare_size)
                sys.stdout.write("ECC layout: %s\n" % self.ecclayout)
                sys.stdout.write("Endianess: %s\n" % self.endianess)

    def _auto_detect_settings(self):
        valid_page_sizes = [512, 1024, 2048, 4096, 8192, 16384, -1]
        valid_spare_sizes = []

        for page_size in valid_page_sizes:
            if page_size != -1:
                valid_spare_sizes.append(page_size / 32)

        # Spare data should start at the end of the page; if we can identify it,
        # then we know the page size used.
        for page_size in valid_page_sizes:
            if page_size == -1:
                raise Exception("Auto-detection failed: Could not locate start of spare data section.")

            if self.sample_data[page_size:].startswith(self.SPARE_START_LITTLE_ENDIAN_ECC):
                self.page_size = page_size
                self.ecclayout = True
                self.endianess = YAFFS.LITTLE_ENDIAN
                break
            elif self.sample_data[page_size:].startswith(self.SPARE_START_LITTLE_ENDIAN_NO_ECC):
                self.page_size = page_size
                self.ecclayout = False
                self.endianess = YAFFS.LITTLE_ENDIAN
                break
            elif self.sample_data[page_size:].startswith(self.SPARE_START_BIG_ENDIAN_ECC):
                self.page_size = page_size
                self.ecclayout = True
                self.endianess = YAFFS.BIG_ENDIAN
                break
            elif self.sample_data[page_size:].startswith(self.SPARE_START_BIG_ENDIAN_NO_ECC):
                self.page_size = page_size
                self.ecclayout = False
                self.endianess = YAFFS.BIG_ENDIAN
                break

        try:
            if not self.ecclayout:
                offset = 6
            else:
                offset = 4

            spare_sig = self.sample_data[self.page_size+offset:self.page_size+offset+4] + b"\xFF\xFF"

            self.spare_size = self.sample_data[self.page_size:].index(spare_sig) - 4
        except Exception as e:
            raise Exception("Auto-detection failed: Could not locate end of spare data section.")

        # Sanity check
        if self.spare_size not in valid_spare_sizes:
            raise Exception("Auto-detection failed: Detected an unlikely spare size: %d" % self.spare_size)

class YAFFS(object):
    '''
    Main YAFFS class; all other YAFFS classes are subclassed from this.
    '''

    BIG_ENDIAN = ">"
    LITTLE_ENDIAN = "<"

    # These assume non-unicode YAFFS name lengths
    YAFFS_MAX_NAME_LENGTH       = 255 - 2 # NOTE: This is from observation; YAFFS code #define says 255.
    YAFFS_MAX_ALIAS_LENGTH      = 159

    YAFFS_OBJECT_TYPE_UNKNOWN   = 0
    YAFFS_OBJECT_TYPE_FILE      = 1
    YAFFS_OBJECT_TYPE_SYMLINK   = 2
    YAFFS_OBJECT_TYPE_DIRECTORY = 3
    YAFFS_OBJECT_TYPE_HARDLINK  = 4
    YAFFS_OBJECT_TYPE_SPECIAL   = 5

    DEFAULT_PAGE_SIZE           = 2048
    DEFAULT_SPARE_SIZE          = 64

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
    '''
    YAFFS object type container. The object type is just a 4 byte identifier.
    '''

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
    '''
    Parses and stores relevant data from YAFFS spare data sections.
    Primarily important for retrieving each file object's ID.
    '''

    def __init__(self, data, config):
        self.data = data
        self.config = config

        # YAFFS images built without --yaffs-ecclayout have an extra two
        # bytes before the chunk ID. Possibly an unused CRC?
        if not self.config.ecclayout:
            junk = self.read_next(2)

        self.chunk_id = self.read_next(4)
        self.obj_id = self.read_next(4)

class YAFFSEntry(YAFFS):
    '''
    Parses and stores information from each YAFFS object entry data structure.
    '''

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
    '''
    Main YAFFS file system parser. Primary method is self.next_entry, which yields
    the next object entry in the file system.
    '''

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
    '''
    Class for extracting information and data from a YAFFS file system.
    '''

    def __init__(self, data, config):
        self.file_paths = {}
        self.file_entries = {}
        self.data = data
        self.config = config

    def parse(self):
        with YAFFSParser(self.data, self.config) as parser:
            for entry in parser.next_entry():
                if Compat.has_key(self.file_paths, entry.parent_obj_id):
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
        elif int(entry.yaffs_obj_type) == self.YAFFS_OBJECT_TYPE_HARDLINK:
            sys.stdout.write("\nPoints to file ID: %d\n" % entry.equiv_id)
        else:
            sys.stdout.write("\n")
        sys.stdout.write("File size: 0x%X\n" % entry.file_size)
        sys.stdout.write("File mode: %d\n" % entry.yst_mode)
        sys.stdout.write("File UID: %d\n" % entry.yst_uid)
        sys.stdout.write("File GID: %d\n" % entry.yst_gid)
        #sys.stdout.write("First bytes: %s\n" % entry.file_data[0:16])
        sys.stdout.write("###################################################\n\n")


    def ls(self):
        for (entry_id, entry) in Compat.iterator(self.file_entries):
            self._print_entry(entry)

    def set_mode_owner(self, file_path, entry):
        if self.config.preserve_mode:
            os.chmod(file_path, entry.yst_mode)
        if self.config.preserve_owner:
            os.chown(file_path, entry.yst_uid, entry.yst_gid)

    def extract(self, outdir):
        dir_count = 0
        file_count = 0
        link_count = 0

        # Make it a bytes array for Python3
        outdir = Compat.str2bytes(outdir)

        # Create directories
        for (entry_id, file_path) in Compat.iterator(self.file_paths):
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
        for (entry_id, file_path) in Compat.iterator(self.file_paths):
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
                elif int(entry.yaffs_obj_type) == self.YAFFS_OBJECT_TYPE_SPECIAL:
                    try:
                        os.mknod(file_path, entry.yst_mode, entry.yst_rdev)
                        file_count += 1
                    except Exception as e:
                        sys.stderr.write("Failed to create special device file '%s': %s\n" % (file_path, str(e)))


        # Create hard/sym links
        for (entry_id, file_path) in Compat.iterator(self.file_paths):
            entry = self.file_entries[entry_id]

            if file_path:
                dst = os.path.join(outdir, file_path)

                if int(entry.yaffs_obj_type) == self.YAFFS_OBJECT_TYPE_SYMLINK:
                    src = entry.alias
                    try:
                        os.symlink(src, dst)
                        link_count += 1
                    except Exception as e:
                        sys.stderr.write("WARNING: Failed to create symlink '%s' -> '%s': %s\n" % (dst, src, str(e)))
                elif int(entry.yaffs_obj_type) == self.YAFFS_OBJECT_TYPE_HARDLINK:
                    try:
                        src = os.path.join(outdir, self.file_paths[entry.equiv_id])
                        os.link(src, dst)
                        link_count += 1
                    except Exception as e:
                        sys.stderr.write("WARNING: Failed to create hard link '%s' -> '%s': %s\n" % (dst, src, str(e)))

        return (dir_count, file_count, link_count)

if __name__ == "__main__":

    page_size = None
    spare_size = None
    endianess = None
    ecclayout = None
    preserve_mode = None
    preserve_owner = None
    debug = None
    auto_detect = None

    try:
        in_file = sys.argv[1]
        out_dir = sys.argv[2]
        auto_detect = True
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

    # Either auto-detect configuration settings, or use hard-coded defaults
    if auto_detect:
        config = YAFFSConfig(auto=True, sample_data=data[0:10240])
    else:
        config = YAFFSConfig()

    # Manual settings override default / auto-detected settings
    if spare_size is not None:
        config.spare_size = spare_size
    if page_size is not None:
        config.page_size = page_size
    if endianess is not None:
        config.endianess = endianess
    if ecclayout is not None:
        config.ecclayout = ecclayout
    if preserve_mode is not None:
        config.preserve_mode = preserve_mode
    if preserve_owner is not None:
        config.preserve_owner = preserve_owner
    if debug is not None:
        config.debug = debug

    fs = YAFFSExtractor(data, config)
    sys.stdout.write("Parsing YAFFS objects...\n")
    obj_count = fs.parse()
    sys.stdout.write("Parsed %d objects\n" % obj_count)

    (dc, fc, lc) = fs.extract(out_dir)
    sys.stdout.write("Created %d directories, %d files, and %d links.\n" % (dc, fc, lc))

