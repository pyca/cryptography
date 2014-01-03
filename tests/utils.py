# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

import pytest


def check_for_iface(name, iface, item):
    if name in item.keywords and "backend" in item.funcargs:
        if not isinstance(item.funcargs["backend"], iface):
            pytest.skip("{0} backend does not support {1}".format(
                item.funcargs["backend"], name
            ))


def check_backend_support(item):
    supported = item.keywords.get("supported")
    if supported and "backend" in item.funcargs:
        if not supported.kwargs["only_if"](item.funcargs["backend"]):
            pytest.skip("{0} ({1})".format(
                supported.kwargs["skip_message"], item.funcargs["backend"]
            ))
    elif supported:
        raise ValueError("This mark is only available on methods that take a "
                         "backend")


def load_vectors_from_file(filename, loader):
    base = os.path.join(
        os.path.dirname(__file__), "hazmat", "primitives", "vectors",
    )
    with open(os.path.join(base, filename), "r") as vector_file:
        return loader(vector_file)


def load_nist_vectors(vector_data):
    test_data = None
    data = []

    for line in vector_data:
        line = line.strip()

        # Blank lines, comments, and section headers are ignored
        if not line or line.startswith("#") or (line.startswith("[")
                                                and line.endswith("]")):
            continue

        if line.strip() == "FAIL":
            test_data["fail"] = True
            continue

        # Build our data using a simple Key = Value format
        name, value = [c.strip() for c in line.split("=")]

        # COUNT is a special token that indicates a new block of data
        if name.upper() == "COUNT":
            test_data = {}
            data.append(test_data)
            continue
        # For all other tokens we simply want the name, value stored in
        # the dictionary
        else:
            test_data[name.lower()] = value.encode("ascii")

    return data


def load_cryptrec_vectors(vector_data):
    cryptrec_list = []

    for line in vector_data:
        line = line.strip()

        # Blank lines and comments are ignored
        if not line or line.startswith("#"):
            continue

        if line.startswith("K"):
            key = line.split(" : ")[1].replace(" ", "").encode("ascii")
        elif line.startswith("P"):
            pt = line.split(" : ")[1].replace(" ", "").encode("ascii")
        elif line.startswith("C"):
            ct = line.split(" : ")[1].replace(" ", "").encode("ascii")
            # after a C is found the K+P+C tuple is complete
            # there are many P+C pairs for each K
            cryptrec_list.append({
                "key": key,
                "plaintext": pt,
                "ciphertext": ct
            })
        else:
            raise ValueError("Invalid line in file '{}'".format(line))
    return cryptrec_list


def load_openssl_vectors(vector_data):
    vectors = []

    for line in vector_data:
        line = line.strip()

        # Blank lines and comments are ignored
        if not line or line.startswith("#"):
            continue

        vector = line.split(":")
        vectors.append({
            "key": vector[1].encode("ascii"),
            "iv": vector[2].encode("ascii"),
            "plaintext": vector[3].encode("ascii"),
            "ciphertext": vector[4].encode("ascii"),
        })
    return vectors


def load_hash_vectors(vector_data):
    vectors = []
    key = None
    msg = None
    md = None

    for line in vector_data:
        line = line.strip()

        if not line or line.startswith("#") or line.startswith("["):
            continue

        if line.startswith("Len"):
            length = int(line.split(" = ")[1])
        elif line.startswith("Key"):
            """
            HMAC vectors contain a key attribute. Hash vectors do not.
            """
            key = line.split(" = ")[1].encode("ascii")
        elif line.startswith("Msg"):
            """
            In the NIST vectors they have chosen to represent an empty
            string as hex 00, which is of course not actually an empty
            string. So we parse the provided length and catch this edge case.
            """
            msg = line.split(" = ")[1].encode("ascii") if length > 0 else b""
        elif line.startswith("MD"):
            md = line.split(" = ")[1]
            # after MD is found the Msg+MD (+ potential key) tuple is complete
            if key is not None:
                vectors.append((msg, md, key))
                key = None
                msg = None
                md = None
            else:
                vectors.append((msg, md))
                msg = None
                md = None
        else:
            raise ValueError("Unknown line in hash vector")
    return vectors
