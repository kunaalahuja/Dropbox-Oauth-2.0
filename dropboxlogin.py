import tornado.ioloop
import tornado.web
import tornado.auth
import tornado.gen
import dropbox
import Tkinter, tkFileDialog

 
from tornado import escape, httpclient
from tornado.options import parse_command_line, define, options
 
try:
	import urllib.parse as urllib_parse # py3
except ImportError:
	import urllib as urllib_parse # py2
 
define("port", default=8888)
define("debug", default=False)
 
 
class DropboxMixin(tornado.auth.OAuth2Mixin):
	"""Dropbox authentication using OAuth2.
 
	https://www.dropbox.com/developers/core/docs
 
	"""
	_OAUTH_AUTHORIZE_URL = "https://www.dropbox.com/1/oauth2/authorize"
	_OAUTH_ACCESS_TOKEN_URL = "https://api.dropbox.com/1/oauth2/token"
	_OAUTH_SETTINGS_KEY = 'dropbox_oauth'
 
	@property
	def oauth_settings(self):
		return self.settings[self._OAUTH_SETTINGS_KEY]
 
	@tornado.auth._auth_return_future
	def get_authenticated_user(self, code, callback):
	
		http = self.get_auth_http_client()
		body = urllib_parse.urlencode({
			"redirect_uri": self.oauth_settings["redirect"],
			"code": code,
			"client_id": self.oauth_settings['key'],
			"client_secret": self.oauth_settings['secret'],
			"grant_type": "authorization_code",
		})
 
		http.fetch(
			self._OAUTH_ACCESS_TOKEN_URL,
			self.async_callback(self._on_access_token, callback),
			method="POST",
			headers={'Content-Type': 'application/x-www-form-urlencoded'},
			body=body
		)
		
			
	def get_account_info(self, code, callback):
	
		http = self.get_auth_http_client()
		body = urllib_parse.urlencode({
			"redirect_uri": self.oauth_settings["redirect"],
			"code": code,
			"client_id": self.oauth_settings['key'],
			"client_secret": self.oauth_settings['secret'],
			"grant_type": "authorization_code",
		})
 
		http.fetch(
			self._OAUTH_ACCESS_TOKEN_URL,
			self.async_callback(self._on_access_token, callback),
			method="POST",
			headers={'Content-Type': 'application/x-www-form-urlencoded'},
			body=body
		)
		
 
	def _on_access_token(self, future, response):
	
		if response.error:
			msg = 'Dropbox auth error: {}'.format(str(response))
			future.set_exception(tornado.auth.AuthError(msg))
			return
 
		args = escape.json_decode(response.body)
		future.set_result(args)
 
	def get_auth_http_client(self):
		return httpclient.AsyncHTTPClient()
 
	def authorize_redirect(self, callback=None):
		kwargs = {
			"redirect_uri": self.oauth_settings	["redirect"],
			"client_id": self.oauth_settings["key"],
			"callback": callback,
			"extra_params": {"response_type": "code"}
		}
 
		return super(DropboxMixin, self).authorize_redirect(**kwargs)
 
 
class AuthHandler(tornado.web.RequestHandler, DropboxMixin):
	@tornado.web.asynchronous
	@tornado.gen.coroutine
	def get(self):
		code = self.get_argument("code", None)
 
		if code:
			user = yield self.get_authenticated_user(code=code)
 
			self.set_secure_cookie("oauth_user", user.get("uid", ""))
			self.set_secure_cookie("oauth_token", user.get("access_token", ""))
 
			self.redirect("/")
		else:
			yield self.authorize_redirect()
 
 
class MainHandler(tornado.web.RequestHandler):
	def get_current_user(self):
		print("in get_current_user")
		return self.get_secure_cookie("oauth_user")
 
	def get(self):
		print("in get")
		user = self.get_current_user()
		print("user")
		print(user)		
		if not user:
			raise tornado.web.HTTPError(401, "Access denied")
 
		
		oauth2_access_token = self.get_secure_cookie("oauth_token")
		client = dropbox.client.DropboxClient(oauth2_access_token)
		user1 = client.account_info()
 			
		self.write("Welcome back " + user1['display_name'] )
 
		root = Tkinter.Tk()
		root.withdraw()

		file_path = tkFileDialog.askopenfilename()
		print(file_path)
		
		f = open(file_path, 'rb')
		response = client.put_file("/"+file_path, f)

		
handlers = [
(r"/auth", AuthHandler),
(r"/", MainHandler),
]
 
if __name__ == "__main__":
	parse_command_line()
 
	opts = {
		"debug": options.debug,
		"cookie_secret": "NTliOTY5NzJkYTVlMTU0OTAwMTdlNjgzMTA5M2U3OGQ5NDIxZmU3Mg==",
 
		#https://www.dropbox.com/developers
		"dropbox_oauth": {
			"redirect": "http://localhost:{}/auth".format(options.port),
 			"key": "j2y3xc2i6fz6sxi",
			"secret": "vf6yifcx0og4f9l"
		}
	}
 
	application = tornado.web.Application(handlers, **opts)
	application.listen(options.port)
 
	tornado.ioloop.IOLoop.instance().start()
