#!/usr/bin/env python2
# encoding: utf-8
"""
    Mount public owncloud shares
    Copyright (c) 2015, Phillip Berndt

    Syntax: ./owncloudfs.py <mountpoint> <public share url> [password]

    Note that while public shares can be set up to be written to, this
    functionality is restricted:

        * Files cannnot be deleted, renamed or moved
        * Directories cannot be created or removed

    (It should be quite easy to extend this to also allow access for
     authenticated users, but before you take the effort note that
     you probably also have WebDAV as an option. Further note that
     owncloud supports unauthenticated WebDAV access, see
       https://github.com/owncloud/core/pull/8353
     You should check if your installation has this feature enabled
     before using this script, as WebDAV access is probably more
     efficient.)

"""
import codecs
import datetime
import errno
import fuse
import io
import json
import mimetypes
import os
import re
import sys
import time
import urllib
import urllib2
import uuid


" Code to encode multipart/form-data requests for file uploads {{{ "
# Taken from http://code.activestate.com/recipes/578668-encode-multipart-form-data-for-uploading-files-via/
class MultipartFormdataEncoder(object):
    def __init__(self):
        self.boundary = uuid.uuid4().hex
        self.content_type = 'multipart/form-data; boundary={}'.format(self.boundary)

    @classmethod
    def u(cls, s):
        if sys.hexversion < 0x03000000 and isinstance(s, str):
            s = s.decode('utf-8')
        if sys.hexversion >= 0x03000000 and isinstance(s, bytes):
            s = s.decode('utf-8')
        return s

    def iter(self, fields, files):
        """
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, file-type) elements for data to be uploaded as files
        Yield body's chunk as bytes
        """
        encoder = codecs.getencoder('utf-8')
        for (key, value) in fields:
            key = self.u(key)
            yield encoder('--{}\r\n'.format(self.boundary))
            yield encoder(self.u('Content-Disposition: form-data; name="{}"\r\n').format(key))
            yield encoder('\r\n')
            if isinstance(value, int) or isinstance(value, float):
                value = str(value)
            yield encoder(self.u(value))
            yield encoder('\r\n')
        for (key, filename, fd) in files:
            key = self.u(key)
            filename = self.u(filename)
            yield encoder('--{}\r\n'.format(self.boundary))
            yield encoder(self.u('Content-Disposition: form-data; name="{}"; filename="{}"\r\n').format(key, filename))
            yield encoder('Content-Type: {}\r\n'.format(mimetypes.guess_type(filename)[0] or 'application/octet-stream'))
            yield encoder('\r\n')
            with fd:
                buff = fd.read()
                yield (buff, len(buff))
            yield encoder('\r\n')
        yield encoder('--{}--\r\n'.format(self.boundary))

    def encode(self, fields, files):
        body = io.BytesIO()
        for chunk, chunk_len in self.iter(fields, files):
            body.write(chunk)
        return self.content_type, body.getvalue()
# }}}

class OwncloudProxy(object): # {{{
    """
        Proxy public OwnCloud shares

        TODO Handle login timeouts (by simply re-running obtain_login_token)
    """

    class OwncloudProxyException(RuntimeError):
        pass

    REQUEST_TOKEN_REGEX  = re.compile('name="requesttoken"\s+value="([^"]+)"')
    SHARE_URL            = re.compile("^(?P<base>.+)public.php\?.+t=(?P<token>[^&]+)(?:&|$)")

    LIST_SERVICE_PATH    = "index.php/apps/files_sharing/ajax/list.php"
    UPLOAD_SERVICE_PATH  = "index.php/apps/files/ajax/upload.php"
    PUBLIC_SERVICE_PATH  = "public.php"

    def __init__(self, url, password=None):
        """Initialize the class using a URL of a public share, i.e.
                https://.../public.php?service=files&t=....&,
            and the associated password.
        """
        self.url = url
        self.password = password
        self.obtain_login_token()

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, url):
        url_match = self.SHARE_URL.match(url)
        if not url_match:
            raise self.OwncloudProxyException("This program is intended to be used with public owncloud shares")
        self._url = url
        self._url_base = url_match.group("base")
        self._share_token = url_match.group("token")

    def obtain_login_token(self):
        "Used internally to log the user in and obtain both a session cookie and a request token"
        request = urllib2.Request(self.url, urllib.urlencode({"password": self.password}))
        response = urllib2.urlopen(request)
        login_cookie = []
        for cookie in response.info().getheader("Set-Cookie").split(","):
            login_cookie.append(cookie.split(";")[0])
        self._login_cookie = ", ".join(login_cookie)
        response_text = response.read()
        if "The password is wrong" in response_text:
            raise self.OwncloudProxyException("Password is wrong.")
        request_token = self.REQUEST_TOKEN_REGEX.search(response_text).group(1)
        if not request_token:
            raise self.OwncloudProxyException("Login failed")
        self._request_token = request_token

    def new_request(self, url):
        request = urllib2.Request(url)
        request.add_header("Cookie", self._login_cookie)
        request.add_header("requesttoken", self._request_token)
        return request

    def list_directory(self, path):
        "Returns a generator yielding (name, stat() dictionary) tuples"
        request = self.new_request("%s%s?%s" % (self._url_base, self.LIST_SERVICE_PATH, urllib.urlencode({ "t": self._share_token, "dir": path, "sort": "name", "sortdirection": "asc" })))
        response = json.load(urllib2.urlopen(request))
        for entry in response[u"data"][u"files"]:
             mtime = time.mktime(datetime.datetime.strptime(entry[u"date"], "%B %d, %Y %H:%M").timetuple())
             name = entry[u"name"]
             size = int(entry[u"size"])
             is_dir = entry[u"type"] == u"dir"
             yield name, {
                 "st_mode": 0100644 if not is_dir else 040755,
                 "st_mtime": mtime,
                 "st_ctime": mtime,
                 "st_uid": os.getuid(),
                 "st_gid": os.getgid(),
                 "st_size": size,
             }

    def get_file(self, path):
        """Return an opened file for reading

            TODO Add support for Range requests
        """
        directory, filename = os.path.split(path)
        request = self.new_request("%s%s?%s&download" % (self._url_base, self.PUBLIC_SERVICE_PATH, urllib.urlencode({ "service": "files", "t": self._share_token, "path": directory, "files": filename })))
        return urllib2.urlopen(request)

    def put_file(self, path, file_obj):
        "Upload the contents of a given opened file to the cloud"
        directory, filename = os.path.split(path)
        request = self.new_request("%s%s" % (self._url_base, self.UPLOAD_SERVICE_PATH))
        content_type, post_body = MultipartFormdataEncoder().encode({
            "requesttoken": self._request_token,
            "dirToken": self._share_token,
            "subdir": directory,
            "file_directory": "",
            "resolution": "replace",
            "password": self.password,
        }.items(), (("files[]", filename, file_obj),))
        request.add_data(post_body)
        request.add_header("Content-Type", content_type)
        try:
            return urllib2.urlopen(request).read()
        except urllib2.HTTPError as e:
            if e.code != 500:
                raise
        return ""

class OwncloudOperations(fuse.LoggingMixIn, fuse.Operations):
    """
        FUSE layer for Owncloud

        This class keeps track of open files to avoid excessive Owncloud
        access. Files are read upon open()ing them and only written back once
        flush() is called. This also means that multiple read()s on an open
        file always lead a consistent complete file.

        stat() is also cached on a per-directory base because Owncloud only
        allows to access the information on that basis. The cache is flushed
        whenever readdir() is called.
    """
    def __init__(self, owncloud_proxy):
        "Takes an OwncloudProxy instance as an argument"
        self.owncloud_proxy = owncloud_proxy
        self.fd = 0
        self.stat_cache = {}
        self.open_files = {}

    def create(self, path, mode):
        self.fd += 1
        self.open_files[self.fd] = { "path": path, "contents": "" }
        return self.fd

    def flush(self, path, fh):
        self.owncloud_proxy.put_file(self.open_files[fh]["path"], io.BytesIO(self.open_files[fh]["contents"]))

    def getattr(self, path, fh=None):
        if path == "/":
            # Root directory must be accessible
            return { "st_mode": 040755 }
        for file_fh, file_obj in self.open_files.items():
            if file_fh == fh or file_obj["path"] == path:
                # Use up to date size for open files
                return {
                    "st_mode": 0100644,
                    "st_size": len(file_obj["contents"]),
                    "st_mtime": time.time(),
                    "st_ctime": time.time(),
                    "st_uid": os.getuid(),
                    "st_gid": os.getgid(),
                }
        directory, filename = os.path.split(path)
        if directory not in self.stat_cache:
            self.stat_cache[directory] = list(self.owncloud_proxy.list_directory(directory))
        for name, stat in self.stat_cache[directory]:
            if name == filename:
                return stat
        raise fuse.FuseOSError(errno.ENOENT)

    def open(self, path, flags):
        self.fd += 1
        try:
            self.getattr(path)
            exists = True
        except:
            exists = False
        contents = ""
        if not exists and not flags & os.O_CREAT:
            raise fuse.FuseOSError(errno.ENOENT)
        if exists and not (flags & os.O_TRUNC and (flags & os.O_RDWR or flags & os.O_WRONLY)):
            contents = self.owncloud_proxy.get_file(path).read()
        self.open_files[self.fd] = { "path": path, "contents": contents }
        return self.fd

    def release(self, path, fh):
        del self.open_files[fh]
        return 0

    def truncate(self, path, length, fh=None):
        for file_fh, file_obj in self.open_files.items():
            if file_fh == fh or file_obj["path"] == path:
                file_obj["contents"] = file_obj["contents"][:length]

    def read(self, path, size, offset, fh):
        return self.open_files[fh]["contents"][offset:offset+size]

    def readdir(self, path, fh):
        retval = [ (".", {}, 0), ("..", {}, 0) ]
        dir_entries = list(self.owncloud_proxy.list_directory(path))
        self.stat_cache[path] = dir_entries
        for name, stat in dir_entries:
            retval.append((name, stat, 0))
        return retval

    def write(self, path, data, offset, fh):
        contents = self.open_files[fh]["contents"]
        if len(contents) < offset:
            contents += "\0" * (offset - len(contents))
        contents = contents[:offset] + data + contents[offset + len(data):]
        self.open_files[fh]["contents"] = contents
        return len(data)

if __name__ == '__main__':
    if len(sys.argv) not in (3, 4):
        print "Syntax: owncloudfs.py <url> <mountpoint> [password]"
        sys.exit(1)

    #import logging
    #logging.getLogger().setLevel(logging.DEBUG)
    #logging.getLogger().addHandler(logging.StreamHandler())

    url = sys.argv[1]
    mountpoint = sys.argv[2]
    password = sys.argv[3] if len(sys.argv) == 4 else ""

    print "Logging you in.."
    proxy = OwncloudProxy(url, password)

    print "Starting up FUSE.."
    fuse_instance = fuse.FUSE(OwncloudOperations(proxy), mountpoint, foreground=True)
