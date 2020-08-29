import functools
import os
import re
import subprocess

import bs4


class NotebookTester:
    def __init_subclass__(cls):
        cls.test_notebooks = {
            '_'.join([re.sub(r'\W+', '', t).lower()
                      for t in m.groups()[0].replace('-', '_').split()]):
            os.path.join(cls.notebooks_path, m.string) for m in filter(
                None, map(lambda n: re.match(r'^(.+)-test.ipynb$', n),
                          os.listdir(cls.notebooks_path)))}

        for name, path in cls.test_notebooks.items():
            setattr(cls, f'test_{name}', functools.partialmethod(cls.execute, name, path))

    def execute(self, name, path):
        subprocess.Popen([
            'jupyter', 'nbconvert', '--execute', '--allow-errors',
            '--ExecutePreprocessor.timeout=-1', path
        ]).communicate()
        html_path = os.path.abspath(re.sub(r'.ipynb$', '.html', path))

        with open(html_path) as html:
            soup = bs4.BeautifulSoup(html.read(), features='html.parser')

        errors = ', '.join(list(self.yield_error_input_numbers(soup)))

        assert not errors, f'Notebook {path} {errors} failed - ' \
            f'check file://{html_path}'

        check_soup_method = getattr(self, f'check_{name}', None)

        if check_soup_method:
            check_soup_method(soup)

    @staticmethod
    def assert_cell_stdout(soup, number):
        cell = soup.find(
            'div', {'class': 'input_prompt'}, string=f'In\xa0[{number}]:'
        ).parent.parent
        stdout = cell.find('div', {'class': 'output_stdout'})

        assert stdout, f'No stdout in cell {number}'

        return stdout

    @staticmethod
    def yield_error_input_numbers(soup):
        for error_soup in soup.find_all('div', {'class': 'output_error'}):
            parents = error_soup.parents
            cell = [next(parents) for x in range(4)][-1]
            content = cell.find('div', {'class': 'input_prompt'}).contents[0]

            yield content.replace('\xa0', '').replace(':', '')
