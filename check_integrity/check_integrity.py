#!/usr/bin/env python3
# vim:fileencoding=utf8
"""
    Simple integrity checker informing admin about updated files

    Copyright (c) 2016, Phillip Berndt

    The script records md5 sums of every file on the system in
    directories that ought not to change often and informs the user
    if any of them changes, and if this change is due to a system
    update (on Debian systems; you'll have to adjust this to non-apt
    systems) or not, and if there are enhanced capability / suid
    programs around.

    Note that this script does not even try to secure its operation.
    If an attacker gains root permissions, it is very easy for him to
    cheat it into not complaining. (In fact, he only needs to run it
    once, because check_integrity then updates its database.)
"""
import collections
import ctypes
import glob
import hashlib
import itertools
import os
import shelve
import warnings

# Location of the file database; can be world readable, because
# it only stores hashes
DATABASE_FILE = "/var/lib/verify"

# Directories to generally ignore for files from system_md5sums()
BANNED_PACKAGE_ROOTS = ("/var", "/opt")

# Directories in the system root that do not contain files from
# system_md5sums that should be ignored
BANNED_ROOTS = ("/proc", "/sys", "/dev")

try:
    libcap = ctypes.CDLL("libcap.so.2")

    def get_file_capabilities(filename):
        "Check if a file has special capabilites set"
        caps = libcap.cap_get_file(filename)
        cap_text = None
        if caps != 0:
            cap_text_ptr = libcap.cap_to_text(caps, 0)
            cap_text = ctypes.cast(cap_text_ptr, ctypes.c_char_p).value
            libcap.cap_free(cap_text_ptr)
            libcap.cap_free(caps)
        return cap_text
except:
    def get_file_capabilities(filename):
        "Dummy function if libcap.so is unavailable"
        return None

def get_suid_and_sgid(filename):
    "Check if a file is suid or guid"
    try:
        return os.stat(filename).st_mode & 0o6000
    except:
        return False

def system_md5sums():
    """Return dictionary of files known to the OS, with iterable of possible
    md5sums as value, for systems using dpkg (Debian)"""
    os_files = collections.defaultdict(lambda: [])
    if not os.path.isdir("/var/lib/dpkg/info"):
        warnings.warn("/var/lib/dpkg/info does not exist - not a Debian system? Will not be able to tell system and non-system files apart")
    for listfile in glob.glob("/var/lib/dpkg/info/*.md5sums"):
        for line in open(listfile, "r", encoding="UTF-8"):
            md5sum, filename = line.strip().split(None, 1)
            filename = "/%s" % filename
            os_files[filename].append(md5sum)
    return os_files

def md5sum(filename):
    "Return a file's md5sum"
    fhash = hashlib.md5()
    with open(filename, "rb") as fd:
        for buf in iter(lambda: fd.read(1024), b""):
            fhash.update(buf)
    return fhash.hexdigest()

def md5sum_buf(data):
    "Return the md5sum of some data"
    bhash = hashlib.md5()
    bhash.update(data)
    return bhash.hexdigest()

def list_files(root):
    "Yield all files in root"
    for (dirpath, dirnames, filenames) in os.walk(root):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if os.path.isfile(filepath):
                yield filepath

def annotate_files_with_md5sum(iterable):
    "Annotate a list of files with their md5sum"
    for filepath in iterable:
        try:
            md5 = md5sum(filepath)
        except:
            md5 = "-"
        yield filepath, md5

def filter_and_annotate_files_for_executables(iterable):
    "Filter a list of files for executables, and annotate with stat"
    for filepath in iterable:
        try:
            stat = os.stat(filepath).st_mode
        except:
            continue
        if not stat & 0o111: # Executable
            continue
        yield filepath, stat

def list_files_with_enhanced_caps(root):
    "Yield all files having suid or elevated capabilities"
    for filepath, stat in filter_and_annotate_files_for_executables(list_files(root)):
        if stat & 0o6000 or get_file_capabilities(filepath): # 0o6000 = suid | sgid
            yield filepath

def list_files_with_md5sum(root):
    "Return a generator yielding all files in root with their md5sums"
    return annotate_files_with_md5sum(list_files(root))

def output(filename, status):
    try:
        print("%-60s %s" % (status, filename))
    except UnicodeError:
        print("%-60s '%s'" % (status, filename.encode("ascii", errors="backslashreplace").decode()))

if __name__ == "__main__":
    os.nice(10)

    database = shelve.open(DATABASE_FILE) # entries are tuples: (md5sum, capability md5sum, suid/sgid digit)

    os_files = system_md5sums()

    system_roots = list(filter(lambda x: os.path.isdir(x) and x not in BANNED_PACKAGE_ROOTS, {"/%s" % x[1:].split("/")[0] for x in os_files.keys()}))
    suid_check_roots = filter(lambda x: os.path.isdir("/%s" % x) and "/%s" % x not in system_roots and "/%s" % x not in BANNED_ROOTS, os.listdir("/"))

    files = itertools.chain(
        itertools.chain(*map(list_files_with_md5sum, system_roots)),
        itertools.chain(*(annotate_files_with_md5sum(list_files_with_enhanced_caps(x)) for x in suid_check_roots)),
        annotate_files_with_md5sum(filter(os.path.isfile, os.listdir("/")))
    )
    for filename, hashsum in files:
        filename_md5 = md5sum_buf(filename.encode("unicode_escape"))
        is_known = filename_md5 in database

        is_changed = is_known and database[filename_md5][0] != hashsum
        base_filename = os.path.realpath(filename)
        base_filename_md5 = md5sum_buf(base_filename.encode("unicode_escape"))
        is_os_file = base_filename in os_files
        is_os_changed = is_os_file and hashsum not in os_files[base_filename]
        capabilities = get_file_capabilities(filename)
        capabilities_md5 = md5sum_buf(capabilities.encode("unicode_escape")) if capabilities else "-"
        is_sugid = get_suid_and_sgid(filename)

        if is_known:
            if is_sugid and is_sugid != database[filename_md5][2] or \
               capabilities and capabilities_md5 != database[filename_md5][1]:
                is_changed = True

        if not is_known:
            info = ["New"]
            if is_sugid:
                info.append("SUID")
            if capabilities:
                info.append("capability-enabled")
            if not is_os_file:
                info.append("file, not owned by OS")
            elif is_os_changed:
                info.append("file, owned by OS but changed from vendor version")
            if len(info) > 1:
                output(filename, " ".join(info))
        elif is_changed:
            info = ["Updated"]
            if is_sugid:
                info.append("SUID")
            if capabilities:
                info.append("capability-enabled")
            if is_os_changed:
                info.append("file, owned by OS, changed from vendor version")
                output(filename, " ".join(info))
            elif not is_os_file:
                info.append("file, not owned by OS")
                output(filename, " ".join(info))

        database[filename_md5] = (hashsum, capabilities_md5, is_sugid)

    database.close()
