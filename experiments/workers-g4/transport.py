"""Retry TLS setup only. Never replay an HTTP request or ambiguous mutation."""
import http.client, ssl, urllib.request
class Connection(http.client.HTTPSConnection):
    def connect(self):
        for attempt in range(3):
            try:
                return super().connect()
            except ssl.SSLEOFError:
                if self.sock is not None:
                    self.sock.close()
                self.sock = None
                if attempt == 2:
                    raise
class HTTPS(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(Connection,request,context=self._context)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None
opener=urllib.request.build_opener(HTTPS(),NoRedirect())
