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

import markdown
import os.path
import re
import torndb
import tornado.auth
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import unicodedata

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

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/feed", FeedHandler),
            (r"/downloads", DownloadHandler),
            (r"/gallery", GalleryHandler),
            (r"/browse", BrowseHandler),
            (r"/serve/([^/]+)", FileServeHandler),
            (r"/entry/([^/]+)", EntryHandler),
            (r"/raw/([^/]+)", RawEntryHandler),
            (r"/compose", ComposeHandler),
            (r"/profile", ProfileHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            site_title=u"AnvilMG Script Directory",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            ui_modules={"Entry": EntryModule},
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            debug=True,
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
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY updated DESC LIMIT 15")
        self.render("browse.html", entries=entries)

    def post(self):
        raise tornado.web.HTTPError(404)


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
        file = self.db.get("SELECT * FROM file_name WHERE slug = %s", file_name)


class EntryHandler(BaseHandler):
    def get(self, slug):
        entry = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
        if not entry: raise tornado.web.HTTPError(404)
        author = self.db.get("SELECT * FROM authors WHERE id = %s", entry.author_id)
        if not author: raise tornado.web.HTTPError(404)
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
        entries = self.db.query("SELECT title, description FROM entries ORDER BY published "
                                "DESC LIMIT 100")
        self.set_header("Content-Type", "application/atom+xml")
        self.render("feed.xml", entries=entries)


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
                "UPDATE entries SET description = %s, body = %s "
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
                "published) VALUES (%s,%s,%s,%s,%s,UTC_TIMESTAMP())",
                self.current_user.id, title, slug, description, body)
        self.redirect("/entry/" + slug)


class AuthLoginHandler(BaseHandler, tornado.auth.GoogleMixin):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("openid.mode", None):
            self.get_authenticated_user(self.async_callback(self._on_auth))
            return
        self.authenticate_redirect()

    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Google auth failed")
        author = self.db.get("SELECT * FROM authors WHERE email = %s",
                             user["email"])
        if not author:
            # Auto-create first author
            any_author = self.db.get("SELECT * FROM authors LIMIT 1")
            if not any_author:
                author_id = self.db.execute(
                    "INSERT INTO authors (email,name) VALUES (%s,%s)",
                    user["email"], user["name"])
            else:
                self.redirect("/")
                return
        else:
            author_id = author["id"]
        self.set_secure_cookie("anvilscript_cookie", str(author_id))
        self.redirect(self.get_argument("next", "/"))


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("anvilscript_cookie")
        self.redirect(self.get_argument("next", "/"))


class EntryModule(tornado.web.UIModule):
    def render(self, entry, author=None):
        return self.render_string("modules/entry.html", entry=entry, author=author)


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
