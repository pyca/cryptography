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

import os.path


def load_nist_vectors(vector_data, op):
    section, count, data = None, None, {}

    for line in vector_data:
        line = line.strip()

        # Blank lines are ignored
        if not line:
            continue

        # Lines starting with # are comments
        if line.startswith("#"):
            continue

        # Look for section headers
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            data[section] = {}
            continue

        # Build our data using a simple Key = Value format
        name, value = line.split(" = ")

        # COUNT is a special token that indicates a new block of data
        if name.upper() == "COUNT":
            count = value
            data[section][count] = {}
        # For all other tokens we simply want the name, value stored in
        # the dictionary
        else:
            data[section][count][name.lower()] = value.encode("ascii")

    # We want to test only for a particular operation, we sort them for the
    # benefit of the tests of this function.
    return [v for k, v in sorted(data[op].items(), key=lambda kv: kv[0])]


def load_nist_vectors_from_file(filename, op):
    base = os.path.join(
        os.path.dirname(__file__), "primitives", "vectors", "NIST",
    )
    with open(os.path.join(base, filename), "r") as vector_file:
        return load_nist_vectors(vector_file, op)


def load_cryptrec_vectors_from_file(filename):
    base = os.path.join(
        os.path.dirname(__file__), "primitives", "vectors", "CRYPTREC",
    )
    with open(os.path.join(base, filename), "r") as vector_file:
        return load_cryptrec_vectors(vector_file)


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
    return cryptrec_list


def load_openssl_vectors_from_file(filename):
    base = os.path.join(
        os.path.dirname(__file__), "primitives", "vectors", "OpenSSL",
    )
    with open(os.path.join(base, filename), "r") as vector_file:
        return load_openssl_vectors(vector_file)


def load_openssl_vectors(vector_data):
    vectors = []

    for line in vector_data:
        line = line.strip()

        # Blank lines and comments are ignored
        if not line or line.startswith("#"):
            continue

        vector = line.split(":")
        params = (
            # key
            vector[1].encode("ascii"),
            # iv
            vector[2].encode("ascii"),
            # plaintext
            vector[3].encode("ascii"),
            # ciphertext
            vector[4].encode("ascii")
        )
        vectors.append(params)
    return vectors
