#! /usr/bin/env python3

import sys
if sys.version_info.major < 3:
    sys.stderr.write("{} requires Python 3\n".format(sys.argv[0]))
    sys.exit(1)

import binascii
import base64
import binhex
import uu
import io # for uuencode
import codecs # for ROT13
import urllib.parse # for percent-encoding.
import quopri
import html
import collections
import tempfile
import logging

def wrap_uu(func):
    """
    Convert a function
        f(in_file, out_file)
    to
        out_bytes = f(in_string)
    """
    def new_func(in_bytes):
        in_file = io.BytesIO(in_bytes)
        out_file = io.BytesIO()
        func(in_file, out_file)
        out_file.seek(0)
        return out_file.read()
    return new_func

def wrap_binhex(func):
    """
    Convert a function
        f(in_filename, out_filename)
    to
        out_bytes = f(in_bytes)
    """
    def new_func(in_bytes):
        in_file = tempfile.NamedTemporaryFile()
        in_file.write(in_bytes)
        in_file.seek(0)
        out_file = tempfile.NamedTemporaryFile()
        func(in_file.name, out_file.name)
        out_file.seek(0)
        out_bytes = out_file.read()
        return out_bytes

    return new_func

def wrap_rot13(func):
    # We can't use functools.partial
    # because codecs.encode takes no keyword arguments.
    def new_func(in_bytes):
        # I'm not sure this is correct,
        # but 'rot-13' is str-to-str only.
        in_str = in_bytes.decode()
        out_str = func(in_str, 'rot-13')
        return out_str.encode()
    return new_func

def wrap_html(func):
    def new_func(in_bytes):
        in_str = in_bytes.decode()
        out_str = func(in_str)
        return out_str.encode()
    return new_func

def wrap_percent_encode(in_string):
    return urllib.parse.quote_from_bytes(in_string).encode()

decode_string_funcs = collections.OrderedDict()
decode_string_funcs['Base64'] = base64.standard_b64decode
decode_string_funcs['Base32'] = base64.b32decode
decode_string_funcs['Base16'] = base64.b16decode
decode_string_funcs['Ascii85'] = base64.a85decode
decode_string_funcs['Base85'] = base64.b85decode
decode_string_funcs['Uuencoding'] = wrap_uu(uu.decode)
decode_string_funcs['BinHex'] = wrap_binhex(binhex.hexbin)
decode_string_funcs['ROT13'] = wrap_rot13(codecs.decode)
decode_string_funcs['MIME quoted-printable'] = quopri.decodestring
decode_string_funcs['Percent-encoding'] = urllib.parse.unquote_to_bytes
decode_string_funcs['HTML'] = wrap_html(html.unescape)

encode_string_funcs = collections.OrderedDict()
encode_string_funcs['Base64'] = base64.standard_b64encode
encode_string_funcs['Base32'] = base64.b32encode
encode_string_funcs['Base16'] = base64.b16encode
encode_string_funcs['Ascii85'] = base64.a85encode
encode_string_funcs['Base85'] = base64.b85encode
encode_string_funcs['Uuencoding'] = wrap_uu(uu.encode)
encode_string_funcs['BinHex'] = wrap_binhex(binhex.binhex)
encode_string_funcs['ROT13'] = wrap_rot13(codecs.encode)
encode_string_funcs['MIME quoted-printable'] = quopri.encodestring
encode_string_funcs['Percent-encoding'] = wrap_percent_encode
encode_string_funcs['HTML'] = wrap_html(html.escape)

def decode_bytes(unknown_bytes, func, encoding):
    assert isinstance(unknown_bytes, bytes), \
        "{0} is type {1} not an instance of 'bytes' in encoding {2}".format(repr(unknown_bytes), type(unknown_bytes), encoding)

    decoded_bytes = None
    try:
        decoded_bytes = func(unknown_bytes)
    except binascii.Error:
        pass
    except binhex.Error:
        pass
    except uu.Error:
        pass
    except ValueError:
        pass
    return decoded_bytes

# TODO: make this just decode and return a dict
# instead of also printing the output
# to facilitate testing.
def decode_and_print(unknown_bytes):
    if unknown_bytes == b'':
        logging.error("no input to decode")
    failed_encodings = []
    no_difference = []
    output_dict = collections.OrderedDict()
    for name, func in decode_string_funcs.items():
        decoded_bytes = decode_bytes(unknown_bytes, func, name)
        if decoded_bytes:
            if decoded_bytes == unknown_bytes:
                no_difference.append(name)
            else:
                try:
                    unicode_str = decoded_bytes.decode()
                    output_dict[name] = unicode_str
                except UnicodeDecodeError:
                    output_dict[name] = repr(decoded_bytes)
        else:
            failed_encodings.append(name)
    if output_dict:
        column_chars = max([len(name) for name in output_dict.keys()])
        for name, output in output_dict.items():
            print("{} : {}".format(name.ljust(column_chars), output))
    print("Failed to decode:", ", ".join(failed_encodings))
    print("Output same as input:", ", ".join(no_difference))

def self_test():
    import string
    test_string = string.printable
    # Todo: test unicode as well, e.g. unicodedata.lookup('snowman')
    test_bytes = test_string.encode()
    print("Encoding and decoding this string: "+repr(test_string))
    for encoding, func in encode_string_funcs.items():
        print("======== " + encoding + " ========")
        encoded_bytes = func(test_bytes)
        print(encoded_bytes)
        decode_and_print(encoded_bytes)
        assert decode_bytes(encoded_bytes, decode_string_funcs[encoding], encoding) == test_bytes, 'Round-tripping printable ASCII characters failed.'

if __name__ == "__main__":
    # Use default encoding.
    if len(sys.argv) != 2:
        print("usage: python try_decodings.py string")
    # TODO: add a --help flag.
    # TODO: add an --encodings flag to list encoding.
    # TODO: add a --reverse flag to encode instead of decode.
    if sys.argv[1] == '--selftest':
        self_test()
    else:
        decode_and_print(sys.argv[1].encode())
