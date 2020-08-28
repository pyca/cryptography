from functools import wraps

from text.conf import settings


def override_conf(**conf):
    def decorator(fn):
        @wraps(fn)
        def override(*args, **kwargs):
            org = {}
            for setting, value in conf.items():
                org[setting] = getattr(settings, setting)
                setattr(settings, setting, value)
            try:
                return fn(*args, **kwargs)
            finally:
                for setting, value in conf.items():
                    setattr(settings, setting, org[setting])
        return override
    return decorator
