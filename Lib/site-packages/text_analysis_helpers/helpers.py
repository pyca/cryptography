import arrow
from jinja2.loaders import PackageLoader
from jinja2 import Environment


def current_date():
    return arrow.utcnow()


def render_analysis_result(analysis_result, template):
    loader = PackageLoader('text_analysis_helpers', 'templates')
    env = Environment(loader=loader)
    template = env.get_template(template)

    return template.render(analysis_result=analysis_result)
