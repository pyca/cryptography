"""
Module with tests for the clearmetadata preprocessor.
"""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

from .base import PreprocessorTestsBase
from ..clearmetadata import ClearMetadataPreprocessor


class TestClearMetadata(PreprocessorTestsBase):
    """Contains test functions for clearmetadata.py"""

    def build_notebook(self):
        notebook = super(TestClearMetadata, self).build_notebook()
        # Add a test field to the first cell
        if 'metadata' not in notebook.cells[0]:
            notebook.cells[0].metadata = {}
        notebook.cells[0].metadata['test_field'] = 'test_value'
        notebook.cells[0].metadata['executeTime'] = dict([('end_time', '09:31:50'), 
                                                    ('start_time', '09:31:49')])
        return notebook

    def build_preprocessor(self):
        """Make an instance of a preprocessor"""
        preprocessor = ClearMetadataPreprocessor()
        preprocessor.enabled = True
        return preprocessor

    def test_constructor(self):
        """Can a ClearMetadataPreprocessor be constructed?"""
        self.build_preprocessor()

    def test_output(self):
        """Test the output of the ClearMetadataPreprocessor"""
        nb = self.build_notebook()
        res = self.build_resources()
        preprocessor = self.build_preprocessor()
        nb, res = preprocessor(nb, res)

        assert not nb.cells[0].metadata 
