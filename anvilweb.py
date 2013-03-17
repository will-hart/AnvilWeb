#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json
import os.path
import re
import torndb
import tornado.auth
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import unicodedata

import rollbar
from tornado.options import define, options

"""
local_settings.py contains the database definitions.  Some
defaults are provided below for local testing purposes
and the production settings are in local_settings.py
"""
try:
    from local_settings import *
except ImportError, e:
    print " * There was an import error getting local_settings - applying defaults"
    define("port", default=8888, help="run on the given port", type=int)
    define("mysql_host", default="127.0.0.1:3306", help="blog database host")
    define("mysql_database", default="anvilscript_testdb", help="blog database name")
    define("mysql_user", default="test_user", help="blog database user")
    define("mysql_password", default="test_pass", help="blog database password")
    define("cookie_secret", default="test_key", help="secret cookie key")
    define("facebook_api_key", default="test_api_key", help="facebook app api key")
    define("facebook_secret", default="test_api_secret", help="facebook api secret")
    define("debug_mode", default=True, help="default debug mode")

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/feed", FeedHandler),
            (r"/downloads", DownloadHandler),
            (r"/gallery", GalleryHandler),
            (r"/browse", BrowseHandler),
            (r"/browse/([0-9]+)", BrowseHandler),
            (r"/serve/([^/]+)", FileServeHandler),
            (r"/entry/([^/]+)", EntryHandler),
            (r"/raw/([^/]+)", RawEntryHandler),
            (r"/compose", ComposeHandler),
            (r"/profile", ProfileHandler),
            (r"/auth/login", GoogleLoginHandler),
            (r"/auth/fblogin", FacebookLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            site_title=u"AnvilMG Script Directory",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            ui_modules={"Entry": EntryModule},
            xsrf_cookies=True,
            cookie_secret=options.cookie_secret,
            facebook_api_key=options.facebook_api_key,
            facebook_secret=options.facebook_secret,
            login_url="/auth/login",
            debug=options.debug_mode,
        )
        tornado.web.Application.__init__(self, handlers, **settings)

        # Have one global connection to the blog DB across all handlers
        self.db = torndb.Connection(
            host=options.mysql_host, database=options.mysql_database,
            user=options.mysql_user, password=options.mysql_password)


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        user_id = self.get_secure_cookie("anvilscript_cookie")
        if not user_id: return None
        return self.db.get("SELECT * FROM authors WHERE id = %s", int(user_id))

    def create_user_or_cookie(self, username, email):
        author = self.db.get("SELECT * FROM authors WHERE email = %s", email)
        if not author:
            author_id = self.db.execute(
                "INSERT INTO authors (email,name) VALUES (%s,%s)",
                email, username)
        else:
            author_id = author["id"]
        self.set_secure_cookie("anvilscript_cookie", str(author_id))
        self.redirect(self.get_argument("next", "/"))


class ProfileHandler(BaseHandler):
    """
    Shows either the user profile or a default page showing
    scripts created by the user
    """
    def get(self):
        raise tornado.web.HTTPError(404)

    def post(self):
        raise tornado.web.HTTPError(404)


class BrowseHandler(BaseHandler):
    """
    Allows browsing of scripts
    """
    def get(self, page=1):
        records_per_page = 15
        offset = records_per_page * (int(page) - 1)
        entries = self.db.query("SELECT * FROM entries ORDER BY updated DESC LIMIT 15 OFFSET %s" % offset)
        self.render("browse.html", entries=entries)

    def post(self, page=1):
        search_term = self.get_argument("search","")
        if search_term == "":
            self.redirect('/browse')

        records_per_page = 15
        offset = records_per_page * (int(page) - 1)
        sql = "SELECT * FROM entries WHERE description LIKE '%%%%%s" % search_term
        sql += "%%%%' ORDER BY updated DESC LIMIT 15 OFFSET %s" % offset
        print sql
        entries = self.db.query(sql)
        self.render("browse.html", entries=entries)


class HomeHandler(BaseHandler):
    def get(self):
        self.render("home.html")


class DownloadHandler(BaseHandler):
    def get(self):
        self.render("download.html")


class GalleryHandler(BaseHandler):
    def get(self):
        self.render("gallery.html")


class FileServeHandler(BaseHandler):
    def get(self, file_name):
        # work out which file to get from the query
        file = self.db.get("SELECT file_path FROM files WHERE file_slug = '%s'" % file_name)
        if not file:
            raise tornado.web.HTTPError(404)
        path = file.file_path
        
        # increase the download count
        sql = "UPDATE files SET downloads = downloads + 1" +\
            " WHERE file_slug = '%s'" % file_name
        print sql
        self.db.execute(sql);
        
        # add headers
        self.set_header("Content-Disposition", "attachment; filename=" + path)
        self.set_header("Content-Type", "application/x-zip-compressed")
        
        # get the download
        with open('files/'+path,'rb') as f:
            self.write(f.read())


class EntryHandler(BaseHandler):
    def get(self, slug):
        entry = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
        if not entry: raise tornado.web.HTTPError(404)
        author = self.db.get("SELECT * FROM authors WHERE id = %s", entry.author_id)
        print "-------"
        print author
        print "=------"
        self.render("entry.html", entry=entry, author=author)


class RawEntryHandler(BaseHandler):
    def get(self, slug):
        entry = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
        if not entry: raise tornado.web.HTTPError(404)
        self.set_header('Content-Type', 'text/plain')
        self.render("raw_entry.html", entry=entry)


class FeedHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT title, description, revision FROM entries ORDER BY published DESC")
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(entries))


class ComposeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        id = self.get_argument("id", None)
        entry = None
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
        self.render("compose.html", entry=entry)

    @tornado.web.authenticated
    def post(self):
        id = self.get_argument("id", None)
        title = self.get_argument("title", "")
        description = self.get_argument("description")
        body = self.get_argument("body", "")
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
            if not entry: raise tornado.web.HTTPError(404)
            slug = entry.slug
            self.db.execute(
                "UPDATE entries SET description = %s, body = %s, revision = revision + 1 "
                "WHERE id = %s", description, body, int(id))
        else:
            slug = unicodedata.normalize("NFKD", title).encode(
                "ascii", "ignore")
            slug = re.sub(r"[^\w]+", " ", slug)
            slug = "-".join(slug.lower().strip().split())
            if not slug: slug = "entry"
            while True:
                e = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
                if not e: break
                slug += "-2"
            self.db.execute(
                "INSERT INTO entries (author_id,title,slug,description,body,"
                "published,revision) VALUES (%s,%s,%s,%s,%s,UTC_TIMESTAMP(),0)",
                self.current_user.id, title, slug, description, body)
        self.redirect("/entry/" + slug)


class GoogleLoginHandler(BaseHandler, tornado.auth.GoogleMixin):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("openid.mode", None):
            self.get_authenticated_user(self.async_callback(self._on_auth))
            return
        self.authenticate_redirect()

    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Google auth failed")
        self.create_user_or_cookie(user['name'], user['email'])


class FacebookLoginHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        my_url = (self.request.protocol + "://" + self.request.host +
                  "/auth/fblogin?next=" +
                  tornado.escape.url_escape(self.get_argument("next", "/")))
        if self.get_argument("code", False):
            self.get_authenticated_user(
                redirect_uri=my_url,
                client_id=self.settings["facebook_api_key"],
                client_secret=self.settings["facebook_secret"],
                code=self.get_argument("code"),
                callback=self._on_auth,
                extra_fields=["email"])
            return
        self.authorize_redirect(redirect_uri=my_url,
                                client_id=self.settings["facebook_api_key"],
                                extra_params={"scope": "email"})

    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Facebook auth failed")
        self.create_user_or_cookie(user['name'], user['email'])


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("anvilscript_cookie")
        self.redirect(self.get_argument("next", "/"))


class EntryModule(tornado.web.UIModule):
    def render(self, entry, author=None):
        return self.render_string("modules/entry.html", entry=entry, author=author)


def main():
    try:
        tornado.options.parse_command_line()
        http_server = tornado.httpserver.HTTPServer(Application())
        http_server.listen(options.port)
        tornado.ioloop.IOLoop.instance().start()
    except:
        # catch-all error reporting to rollbar
        rollbar.report_exc_info(sys.exc_info())


if __name__ == "__main__":
    main()
