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


def load_nist_vectors(vector_data, op, fields):
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
            data[section][count][name.lower()] = value

    # We want to test only for a particular operation
    return [
        tuple(vector[1][f].encode("ascii") for f in fields)
        for vector in sorted(data[op].items(), key=lambda v: v[0])
    ]


def load_nist_vectors_from_file(filename, op, fields):
    base = os.path.join(
        os.path.dirname(__file__), "primitives", "vectors", "NIST",
    )
    with open(os.path.join(base, filename), "r") as vector_file:
        return load_nist_vectors(vector_file, op, fields)


def load_cryptrec_vectors_from_file(filename):
    base = os.path.join(
        os.path.dirname(__file__), "primitives", "vectors", "CRYPTREC",
    )
    with open(os.path.join(base, filename), "r") as vector_file:
        return load_cryptrec_vectors(vector_file)


def load_cryptrec_vectors(vector_data):
    keys, data = [], {}

    for line in vector_data:
        line = line.strip()

        # Blank lines and comments are ignored
        if not line or line.startswith("#"):
            continue

        if line.startswith("K"):
            keys.append(line.split(" : ")[1].replace(" ", ""))
            # create an array under the key to hold all the P+C pairs
            data[keys[-1]] = []
        elif line.startswith("P"):
            # create a new dict to hold the next P+C pair
            data[keys[-1]].append({})
            data[keys[-1]][-1]["P"] = line.split(" : ")[1].replace(" ", "")
        elif line.startswith("C"):
            data[keys[-1]][-1]["C"] = line.split(" : ")[1].replace(" ", "")

    cryptrec_list = []
    for key, value in data.items():
        for pair in value:
            cryptrec_list.append(
                (key.encode("ascii"),
                 pair["P"].encode("ascii"),
                 pair["C"].encode("ascii"))
            )

    return cryptrec_list


def load_openssl_vectors_from_file(filename, op):
    base = os.path.join(
        os.path.dirname(__file__), "primitives", "vectors", "OpenSSL",
    )
    with open(os.path.join(base, filename), "r") as vector_file:
        return load_openssl_vectors(vector_file, op)


def load_openssl_vectors(vector_data, op):
    encrypt, decrypt = [], []

    for line in vector_data:
        line = line.strip()

        # Blank lines and comments are ignored
        if not line or line.startswith("#"):
            continue

        vector = line.split(":")
        args_list = (vector[1].encode("ascii"),
                     vector[2].encode("ascii"),
                     vector[3].encode("ascii"),
                     vector[4].encode("ascii"))
        # some OpenSSL vectors have a final field
        # 0 for decrypt, 1 for encrypt
        if len(vector) == 6:
            if int(vector[5]) == 0:
                decrypt.append(args_list)
            else:
                encrypt.append(args_list)
        else:
            # if they don't have 1 or 0 they are meant for both enc & dec
            # and should be added to both the encrypt and decrypt list
            encrypt.append(args_list)
            decrypt.append(args_list)

    if op == "ENCRYPT":
        return encrypt
    else:
        return decrypt
