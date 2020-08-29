#!/usr/bin/env python
# encoding: utf-8

import sys
from Naked.settings import debug as DEBUG_FLAG

#------------------------------------------------------------------------------
# [ IO class ]
#  interface for all local file IO classes
#------------------------------------------------------------------------------
class IO:
    def __init__(self,filepath):
        self.filepath = filepath

#------------------------------------------------------------------------------
# [ FileWriter class ]
#  writes data to local files
#------------------------------------------------------------------------------
class FileWriter(IO):
    def __init__(self, filepath):
        IO.__init__(self, filepath)

    #------------------------------------------------------------------------------
    # [ append method ]
    #   Universal text file writer that appends to existing file using system default text encoding or utf-8 if throws unicode error
    #   Tests: test_IO.py:: test_file_ascii_readwrite_append, test_file_append_missingfile
    #------------------------------------------------------------------------------
    def append(self, text):
        try:
            from Naked.toolshed.system import file_exists
            if not file_exists(self.filepath): #confirm that file exists, if not raise IOError (assuming that developer expected existing file if using append)
                raise IOError("The file specified for the text append does not exist (Naked.toolshed.file.py:append).")
            with open(self.filepath, 'a') as appender:
                appender.write(text)
        except UnicodeEncodeError as ue:
            self.append_utf8(text) #try writing as utf-8
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to append text to the file with the append() method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ append_utf8 method ]
    #   Text writer that appends text to existing file with utf-8 encoding
    #   Tests: test_IO.py :: test_file_utf8_readwrite_append
    #------------------------------------------------------------------------------
    def append_utf8(self, text):
        try:
            from Naked.toolshed.system import file_exists
            if not file_exists(self.filepath):
                raise IOError("The file specified for the text append does not exist (Naked.toolshed.file.py:append_utf8).")
            import codecs
            import unicodedata
            norm_text = unicodedata.normalize('NFKD', text) # NKFD normalization of the unicode data before write
            with codecs.open(self.filepath, mode='a', encoding="utf_8") as appender:
                appender.write(norm_text)
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to append text to the file with the append_utf8 method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ gzip method (writer) ]
    #   writes data to gzip compressed file
    #   Note: adds .gz extension to filename if user did not specify it in the FileWriter class constructor
    #   Note: uses compresslevel = 6 as default to balance speed and compression level (which in general is not significantly less than 9)
    #   Tests: test_IO.py :: test_file_gzip_ascii_readwrite, test_file_gzip_utf8_readwrite,
    #               test_file_gzip_utf8_readwrite_explicit_decode
    #------------------------------------------------------------------------------
    def gzip(self, text, compression_level=6):
        try:
            import gzip
            if not self.filepath.endswith(".gz"):
                self.filepath = self.filepath + ".gz"
            with gzip.open(self.filepath, 'wb', compresslevel=compression_level) as gzip_writer:
                gzip_writer.write(text)
        except UnicodeEncodeError as ue:
            import unicodedata
            norm_text = unicodedata.normalize('NFKD', text) # NKFD normalization of the unicode data before write
            import codecs
            binary_data = codecs.encode(norm_text, "utf_8")
            with gzip.open(self.filepath, 'wb', compresslevel=compression_level) as gzip_writer:
                gzip_writer.write(binary_data)
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to gzip compress the file with the gzip method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ write method ]
    #   Universal text file writer that writes by system default or utf-8 encoded unicode if throws UnicdeEncodeError
    #   Tests: test_IO.py :: test_file_ascii_readwrite, test_file_ascii_readwrite_missing_file,
    #    test_file_utf8_write_raises_unicodeerror
    #------------------------------------------------------------------------------
    def write(self, text):
        try:
            with open(self.filepath, 'wt') as writer:
                writer.write(text)
        except UnicodeEncodeError as ue:
            self.write_utf8(text) # attempt to write with utf-8 encoding
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to write to requested file with the write() method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ write_as method ]
    #   text file writer that uses developer specified text encoding
    #   Tests: test_IO.py :: test_file_utf8_readas_writeas
    #------------------------------------------------------------------------------
    def write_as(self, text, the_encoding=""):
        try:
            if the_encoding == "": #if the developer did not include the encoding type, raise an exception
                raise RuntimeError("The text encoding was not specified as an argument to the write_as() method (Naked.toolshed.file.py:write_as).")
            import codecs
            with codecs.open(self.filepath, encoding=the_encoding, mode='w') as f:
                f.write(text)
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to write file with the specified encoding using the write_as() method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ write_bin method ]
    #   binary data file writer
    #   Tests: test_IO.py :: test_file_bin_readwrite
    #------------------------------------------------------------------------------
    def write_bin(self, binary_data):
        try:
            with open(self.filepath, 'wb') as bin_writer:
                bin_writer.write(binary_data)
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to write binary data to file with the write_bin method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ safe_write method ] (boolean)
    #   Universal text file writer (writes in default encoding unless throws unicode error) that will NOT overwrite existing file at the requested filepath
    #   returns boolean indicator for success of write based upon test for existence of file (False = write failed because file exists)
    #   Tests: test_IO.py :: test_file_ascii_safewrite, test_file_utf8_safewrite
    #------------------------------------------------------------------------------
    def safe_write(self, text):
        import os.path
        if not os.path.exists(self.filepath): # if the file does not exist, then can write
            try:
                with open(self.filepath, 'wt') as writer:
                    writer.write(text)
                return True
            except UnicodeEncodeError as ue:
                self.write_utf8(text)
                return True
            except Exception as e:
                if DEBUG_FLAG:
                    sys.stderr.write("Naked Framework Error: Unable to write to requested file with the safe_write() method (Naked.toolshed.file.py).")
                raise e
        else:
            return False # if file exists, do not write and return False

    #------------------------------------------------------------------------------
    # [ safe_write_bin method ]
    #   Binary data file writer that will NOT overwrite existing file at the requested filepath
    #   returns boolean indicator for success of write based upon test for existence of file (False = write failed because file exists)
    #------------------------------------------------------------------------------
    def safe_write_bin(self, file_data):
        try:
            import os.path
            if not os.path.exists(self.filepath):
                with open(self.filepath, 'wb') as writer:
                    writer.write(file_data)
                return True
            else:
                return False
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to write to requested file with the safe_write_bin() method (Naked.toolshed.file.py).")
            raise e


    #------------------------------------------------------------------------------
    # [ write_utf8 method ]
    #   Text file writer with explicit UTF-8 text encoding
    #   uses filepath from class constructor
    #   requires text to passed as a method parameter
    #   Tests: test_IO.py :: test_file_utf8_readwrite, test_file_utf8_readwrite_raises_unicodeerror
    #------------------------------------------------------------------------------
    def write_utf8(self, text):
        try:
            import codecs
            f = codecs.open(self.filepath, encoding='utf_8', mode='w')
        except IOError as ioe:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to open file for write with the write_utf8() method (Naked.toolshed.file.py).")
            raise ioe
        try:
            import unicodedata
            norm_text = unicodedata.normalize('NFKD', text) # NKFD normalization of the unicode data before write
            f.write(norm_text)
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to write UTF-8 encoded text to file with the write_utf8() method (Naked.toolshed.file.py).")
            raise e
        finally:
            f.close()

#------------------------------------------------------------------------------
# [ FileReader class ]
#  reads data from local files
#  filename assigned in constructor (inherited from IO class interface)
#------------------------------------------------------------------------------
class FileReader(IO):
    def __init__(self, filepath):
        IO.__init__(self, filepath)

    #------------------------------------------------------------------------------
    # [ read method ] (string)
    #    Universal text file reader that will read utf-8 encoded unicode or non-unicode text as utf-8
    #    returns string or unicode (py3 = string for unicode and non-unicode, py2 = str for non-unicode, unicode for unicode)
    #    Tests: test_IO.py :: test_file_ascii_readwrite, test_file_read_missing_file,
    #------------------------------------------------------------------------------
    def read(self):
        try:
            return self.read_utf8() #reads everything as unicode in utf8 encoding
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to read text from the requested file with the read() method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ read_bin method ] (binary byte string)
    #   Universal binary data file reader
    #   returns file contents in binary mode as binary byte strings
    #   Tests: test_IO.py :: test_file_bin_readwrite, test_file_read_bin_missing_file
    #------------------------------------------------------------------------------
    def read_bin(self):
        try:
            with open(self.filepath, 'rb') as bin_reader:
                data = bin_reader.read()
                return data
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to read the binary data from the file with the read_bin method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ read_as method ] (string with developer specified text encoding)
    #   Text file reader with developer specified text encoding
    #   returns file contents in developer specified text encoding
    #   Tests: test_IO.py :: test_file_utf8_readas_writeas, test_file_readas_missing_file
    #------------------------------------------------------------------------------
    def read_as(self, the_encoding):
        try:
            if the_encoding == "":
                raise RuntimeError("The text file encoding was not specified as an argument to the read_as method (Naked.toolshed.file.py:read_as).")
            import codecs
            with codecs.open(self.filepath, encoding=the_encoding, mode='r') as f:
                data = f.read()
            return data
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to read the file with the developer specified text encoding with the read_as method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ readlines method ] (list of strings)
    #   Read text from file line by line, uses utf8 encoding by default
    #   returns list of utf8 encoded file lines as strings
    #   Tests: test_IO.py :: test_file_readlines, test_file_readlines_missing_file
    #------------------------------------------------------------------------------
    def readlines(self):
        try:
            return self.readlines_utf8() # read as utf8 encoded file
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to read text from the requested file with the readlines() method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ readlines_as method ] (list of developer specified encoded strings)
    #   Read lines from file with developer specified text encoding
    #   Returns a list of developer specified encoded lines from the file
    #   Tests: test_IO.py ::
    #------------------------------------------------------------------------------
    def readlines_as(self, dev_spec_encoding):
        try:
            if dev_spec_encoding == "":
                raise RuntimeError("The text file encoding was not specified as an argument to the readlines_as method (Naked.toolshed.file.py:readlines_as).")
            import codecs
            with codecs.open(self.filepath, encoding=dev_spec_encoding, mode='r') as reader:
                data_list = []
                for line in reader:
                    data_list.append(line)
                return data_list
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to read lines in the specified encoding with the readlines_as method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ readlines_utf8 method ] (list of utf-8 encoded strings)
    #   Read text from unicode file by line
    #   Returns list of file unicode text lines as unicode strings
    #   Tests: test_IO.py :: test_file_readlines_unicode, test_file_readlines_utf8_missing_file
    #------------------------------------------------------------------------------
    def readlines_utf8(self):
        try:
            import codecs
            with codecs.open(self.filepath, encoding='utf-8', mode='r') as uni_reader:
                modified_text_list = []
                for line in uni_reader:
                    import unicodedata
                    norm_line = unicodedata.normalize('NFKD', line) # NKFD normalization of the unicode data before use
                    modified_text_list.append(norm_line)
                return modified_text_list
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: unable to read lines in the unicode file with the readlines_utf8 method (Naked.toolshed.file.py)")
            raise e

    #------------------------------------------------------------------------------
    # [ read_gzip ] (byte string)
    #   reads data from a gzip compressed file
    #   returns the decompressed binary data from the file
    #   Note: if decompressing unicode file, set encoding="utf-8"
    #   Tests: test_IO.py :: test_file_gzip_ascii_readwrite, test_file_gzip_utf8_readwrite,
    #              test_file_read_gzip_missing_file
    #------------------------------------------------------------------------------
    def read_gzip(self, encoding="system_default"):
        try:
            import gzip
            with gzip.open(self.filepath, 'rb') as gzip_reader:
                file_data = gzip_reader.read()
                if encoding in ["utf-8", "utf8", "utf_8", "UTF-8", "UTF8", "UTF_8"]:
                    import codecs
                    file_data = codecs.decode(file_data, "utf-8")
                    import unicodedata
                    norm_data = unicodedata.normalize('NFKD', file_data) # NKFD normalization of the unicode data before passing back to the caller
                    return norm_data
                else:
                    return file_data
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to read from the gzip compressed file with the read_gzip() method (Naked.toolshed.file.py).")
            raise e

    #------------------------------------------------------------------------------
    # [ read_utf8 method ] (string)
    #   read data from a file with explicit UTF-8 encoding
    #   uses filepath from class constructor
    #   returns a unicode string containing the file data (unicode in py2, str in py3)
    #   Tests: test_IO.py :: test_file_utf8_readwrite, test_file_utf8_readwrite_append,
    #           test_file_read_utf8_missing_file
    #------------------------------------------------------------------------------
    def read_utf8(self):
        try:
            import codecs
            f = codecs.open(self.filepath, encoding='utf_8', mode='r')
        except IOError as ioe:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to open file for read with read_utf8() method (Naked.toolshed.file.py).")
            raise ioe
        try:
            textstring = f.read()
            import unicodedata
            norm_text = unicodedata.normalize('NFKD', textstring) # NKFD normalization of the unicode data before returns
            return norm_text
        except Exception as e:
            if DEBUG_FLAG:
                sys.stderr.write("Naked Framework Error: Unable to read the file with UTF-8 encoding using the read_utf8() method (Naked.toolshed.file.py).")
            raise e
        finally:
            f.close()


if __name__ == '__main__':
    pass
