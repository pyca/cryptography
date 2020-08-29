import os
import json
from unittest import TestCase

from ..._compat import decodebytes
from ..nbjson import reads, writes
from .. import nbjson, nbformat, nbformat_minor
from .nbexamples import nb0

from . import formattest


class TestJSON(formattest.NBFormatTest, TestCase):

    nb0_ref = None
    ext = 'ipynb'
    mod = nbjson

    def test_roundtrip_nosplit(self):
        """Ensure that multiline blobs are still readable"""
        # ensures that notebooks written prior to splitlines change
        # are still readable.
        s = writes(nb0, split_lines=False)
        self.assertEqual(nbjson.reads(s),nb0)

    def test_roundtrip_split(self):
        """Ensure that splitting multiline blocks is safe"""
        # This won't differ from test_roundtrip unless the default changes
        s = writes(nb0, split_lines=True)
        self.assertEqual(nbjson.reads(s),nb0)

    def test_splitlines(self):
        """Test splitlines in mime-bundles"""
        s = writes(nb0, split_lines=True)
        raw_nb = json.loads(s)

        for i, ref_cell in enumerate(nb0.cells):
            if ref_cell.source.strip() == 'Cell with attachments':
                attach_ref = ref_cell['attachments']['attachment1']
                attach_json = raw_nb['cells'][i]['attachments']['attachment1']
            if ref_cell.source.strip() == 'json_outputs()':
                output_ref = ref_cell['outputs'][0]['data']
                output_json = raw_nb['cells'][i]['outputs'][0]['data']

        for key, json_value in attach_json.items():
            if key == 'text/plain':
                # text should be split
                assert json_value == attach_ref['text/plain'].splitlines(True)
            else:
                # JSON attachments
                assert json_value == attach_ref[key]

        # check that JSON outputs are left alone:
        for key, json_value in output_json.items():
            if key == 'text/plain':
                # text should be split
                assert json_value == output_ref['text/plain'].splitlines(True)
            else:
                # JSON outputs should be left alone
                assert json_value == output_ref[key]

    def test_read_png(self):
        """PNG output data is b64 unicode"""
        s = writes(nb0)
        nb1 = nbjson.reads(s)
        found_png = False
        for cell in nb1.cells:
            if not 'outputs' in cell:
                continue
            for output in cell.outputs:
                if not 'data' in output:
                    continue
                if 'image/png' in output.data:
                    found_png = True
                    pngdata = output.data['image/png']
                    self.assertEqual(type(pngdata), str)
                    # test that it is valid b64 data
                    b64bytes = pngdata.encode('ascii')
                    raw_bytes = decodebytes(b64bytes)
        assert found_png, "never found png output"

    def test_read_jpeg(self):
        """JPEG output data is b64 unicode"""
        s = writes(nb0)
        nb1 = nbjson.reads(s)
        found_jpeg = False
        for cell in nb1.cells:
            if not 'outputs' in cell:
                continue
            for output in cell.outputs:
                if not 'data' in output:
                    continue
                if 'image/jpeg' in output.data:
                    found_jpeg = True
                    jpegdata = output.data['image/jpeg']
                    self.assertEqual(type(jpegdata), str)
                    # test that it is valid b64 data
                    b64bytes = jpegdata.encode('ascii')
                    raw_bytes = decodebytes(b64bytes)
        assert found_jpeg, "never found jpeg output"

    def test_latest_schema_matches(self):
        """Test to ensure all schema is locked to a known version"""
        assert nbformat == 4
        assert nbformat_minor == 4

    def test_base_version_matches_latest(self):
        """Test to ensure latest version file matches latest verison"""
        with open(os.path.join(os.path.dirname(__file__), '..', 'nbformat.v4.schema.json'), 'r') as schema_file:
            latest_schema = json.load(schema_file)
            with open(os.path.join(os.path.dirname(__file__), '..', 'nbformat.v{major}.{minor}.schema.json'.format(
                    major=nbformat, minor=nbformat_minor)), 'r') as schema_file:
                ver_schema = json.load(schema_file)
            assert latest_schema == ver_schema

    def test_latest_matches_nbformat(self):
        """Test to ensure that the nbformat version matches the description of the latest schema"""
        with open(os.path.join(os.path.dirname(__file__), '..', 'nbformat.v4.schema.json'), 'r') as schema_file:
            schema = json.load(schema_file)
        assert schema['description'] == 'Jupyter Notebook v{major}.{minor} JSON schema.'.format(
            major=nbformat, minor=nbformat_minor
        )
