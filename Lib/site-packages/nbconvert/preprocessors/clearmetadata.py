"""Module containing a preprocessor that removes metadata from code cells"""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

from traitlets import Set
from .base import Preprocessor

class ClearMetadataPreprocessor(Preprocessor):
    """
    Removes all the metadata from all code cells in a notebook.
    """

    def preprocess_cell(self, cell, resources, cell_index):
        """
        All the code cells are returned with an empty metadata field.
        """
        if cell.cell_type == 'code':
            # Remove metadata
            if 'metadata' in cell:
                cell.metadata = {}
        return cell, resources
