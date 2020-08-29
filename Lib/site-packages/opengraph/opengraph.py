# encoding: utf-8

import re
from urllib.request import urlopen
from bs4 import BeautifulSoup

global import_json
try:
    import json
    import_json = True
except ImportError:
    import_json = False

class OpenGraph(dict):
    """
    """

    required_attrs = ['title', 'type', 'image', 'url', 'description']

    def __init__(self, url=None, html=None, scrape=False, **kwargs):
        # If scrape == True, then will try to fetch missing attribtues
        # from the page's body

        self.scrape = scrape
        self._url = url

        for k in kwargs.keys():
            self[k] = kwargs[k]
        
        dict.__init__(self)
                
        if url is not None:
            self.fetch(url)
            
        if html is not None:
            self.parser(html)

    def __setattr__(self, name, val):
        self[name] = val

    def __getattr__(self, name):
        return self[name]
            
    def fetch(self, url):
        """
        """
        raw = urlopen(url)
        html = raw.read()
        return self.parser(html)
        
    def parser(self, html):
        """
        """
        if not isinstance(html,BeautifulSoup):
            doc = BeautifulSoup(html, "html.parser")
        else:
            doc = html
        ogs = doc.html.head.findAll(property=re.compile(r'^og'))
        for og in ogs:
            if og.has_attr(u'content'):
                self[og[u'property'][3:]]=og[u'content']
        # Couldn't fetch all attrs from og tags, try scraping body
        if not self.is_valid() and self.scrape:
            for attr in self.required_attrs:
                if not self.valid_attr(attr):
                    try:
                        self[attr] = getattr(self, 'scrape_%s' % attr)(doc)
                    except AttributeError:
                        pass

    def valid_attr(self, attr):
        return (attr in self) and len(self[attr]) > 0

    def is_valid(self):
        return all([self.valid_attr(attr) for attr in self.required_attrs])
        
    def to_html(self):
        if not self.is_valid():
            return u"<meta property=\"og:error\" content=\"og metadata is not valid\" />"
            
        meta = u""
        for key,value in self.items():
            meta += u"\n<meta property=\"og:%s\" content=\"%s\" />" %(key, value)
        meta += u"\n"
        
        return meta
        
    def to_json(self):
        # TODO: force unicode
        global import_json
        if not import_json:
            return "{'error':'there isn't json module'}"

        if not self.is_valid():
            return json.dumps({'error':'og metadata is not valid'})
            
        return json.dumps(self)
        
    def to_xml(self):
        pass

    def scrape_image(self, doc):
        images = [dict(img.attrs)['src']
            for img in doc.html.body.findAll('img')]

        if images:
            return images[0]

        return u''

    def scrape_title(self, doc):
        return doc.html.head.title.text

    def scrape_type(self, doc):
        return 'other'

    def scrape_url(self, doc):
        return self._url

    def scrape_description(self, doc):
        tag = doc.html.head.findAll('meta', attrs={"name":"description"})
        result = "".join([t['content'] for t in tag])
        return result