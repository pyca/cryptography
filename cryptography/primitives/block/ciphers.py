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


class AES(object):
    name = "AES"
    block_size = 128
    key_sizes = set([128, 192, 256])

    def __init__(self, key):
        super(AES, self).__init__()
        self.key = key

        # Verify that the key size matches the expected key size
        if self.key_size not in self.key_sizes:
            raise ValueError("Invalid key size (%s) for %s".format(
                self.key_size, self.name
            ))

    @property
    def key_size(self):
        return len(self.key) * 8
