import os

TEMPLATE_DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}

INSTALLED_APPS = (
    'text',
)

TEMPLATE_DIRS = (
    os.path.join(os.path.dirname(__file__), 'text', 'templates'),
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.request',
)

MIDDLEWARE_CLASSES = (
    'text.middleware.TextMiddleware',
    'text.middleware.ToolbarMiddleware',
)

ROOT_URLCONF = 'text.urls'
