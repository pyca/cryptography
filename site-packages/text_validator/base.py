import importlib
import sys

import toml


class Plugin:
    def __init__(self, error_callback, config):
        self.config = config
        self.error_callback = error_callback

    def validate_line(self, filename, line_num, line):
        pass

    def validate_first_line(self, filename, line_num, line):
        pass

    def validate_last_line(self, filename, line_num, line):
        pass


class Suite:
    def __init__(self):
        self.plugins = []

    def load_toml(self, filename):
        with open(filename) as f:
            config = toml.load(f)
            for plugin_name, plugin_config in config.items():
                self.add_plugin(plugin_name, plugin_config)

    def add_plugin(self, module_name, config):
        module = importlib.import_module(module_name)
        self.plugins.append(module.plugin(self.error_callback, config))

    def validate_files(self, filenames):
        self.error_count = 0
        for filename in filenames:
            with open(filename, "rb") as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    for plugin in self.plugins:
                        if line_num == 1:
                            plugin.validate_first_line(filename, line_num, line)
                        plugin.validate_line(filename, line_num, line)
                for plugin in self.plugins:
                    plugin.validate_last_line(filename, line_num, line)
        return self.error_count == 0

    def error_callback(self, filename, line_num, offset, error):
        print(f"{filename}:{line_num}:{offset or ''}:{error}", file=sys.stderr)
        self.error_count += 1
