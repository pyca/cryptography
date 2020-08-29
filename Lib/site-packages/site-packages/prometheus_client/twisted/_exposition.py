from __future__ import absolute_import, unicode_literals

from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor

from .. import exposition, REGISTRY

MetricsResource = lambda registry=REGISTRY: WSGIResource(
    reactor, reactor.getThreadPool(), exposition.make_wsgi_app(registry)
)
