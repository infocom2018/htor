#!/usr/bin/env python
#
# Created for HTor project
# basic ideas are stated in submitted 2018 infoCom paper:
#       Link Us If You Can: Enabling Unlinkable Communication on the Internet
# For anonymity of this project, more details will be stated later.

import bcrypt
import concurrent.futures
import MySQLdb
import markdown
import os.path
import re
import subprocess
import torndb
import tornado.escape
from tornado import gen
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import unicodedata
import string
import random
import seccure
import hashlib
import time
from urllib import url2pathname, pathname2url
#   pathname2url:  to the form used in the path component of a URL. This does not produce a complete URL
from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)
define("mysql_host", default="127.0.0.1:3306", help="blog database host")
define("mysql_database", default="blog", help="blog database name")
define("mysql_user", default="root", help="blog database user")
define("mysql_password", default="123456", help="blog database password")

MIN_COMMENTS = 20

# A thread pool to be used for password hashing with bcrypt.
executor = concurrent.futures.ThreadPoolExecutor(2)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/archive", ArchiveHandler),
            # (r"/get/comments/([^/]+)", CommentsHandler),
            (r"/feed", FeedHandler),
            (r"/entry/([^/]+)", EntryHandler),
            (r"/compose", ComposeHandler),
            (r"/auth/create", AuthCreateHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            blog_title=u"Tornado Blog",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            ui_modules={"Entry": EntryModule},
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            debug=True,
        )
        super(Application, self).__init__(handlers, **settings)
        # Have one global connection to the blog DB across all handlers
        self.db = torndb.Connection(
            host=options.mysql_host, database=options.mysql_database,
            user=options.mysql_user, password=options.mysql_password)

        self.maybe_create_tables()

    def maybe_create_tables(self):
        try:
            self.db.get("SELECT COUNT(*) from entries;")
        except MySQLdb.ProgrammingError:
            subprocess.check_call(['mysql',
                                   '--host=' + options.mysql_host,
                                   '--database=' + options.mysql_database,
                                   '--user=' + options.mysql_user,
                                   '--password=' + options.mysql_password],
                                  stdin=open('schema.sql'))
# manually create table, the reference for command can be found in schema.sql


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        user_id = self.get_secure_cookie("blogdemo_user")
        if not user_id: return None
        return self.db.get("SELECT * FROM authors WHERE id = %s", int(user_id))

    def any_author_exists(self):
        return bool(self.db.get("SELECT * FROM authors LIMIT 1"))


class HomeHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC LIMIT 5")
        if not entries:
            self.redirect("/compose")
            return
        self.render("home.html", entries=entries)

# please make sure at least one entry in the entries tables, to make EntryHandler function normally
class EntryHandler(BaseHandler):

    def not_finished(self, cookies, i):
        name = 'user_info'
        name += '' if i == 0 else str(i)
        if name in cookies:
            return name
        else:
            return False

    def random_reply(self, reply, slug):
        entry = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
        if not entry:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", 1)
        entry['pub_success'] = reply
        self.render("entry.html", entry=entry)

    def reply_all_messages(self, reply, slug, htor_user):
        MAX_comments = MIN_COMMENTS
        entry = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
        if not entry:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", 1)
        entry['pub_success'] = reply
        msgs = self.db.query("SELECT * FROM messages WHERE team_id = %s AND id > %s",
                             htor_user['uid'], htor_user['last_message_id'])
        print ("reply_all_messages~")
        if len(msgs) > 0:
            self.db.execute(
                "UPDATE authors SET last_message_id = %s"
                "WHERE id = %s", str(msgs[len(msgs)-1]['id']), htor_user['id'])
        MAX_comments = MAX_comments if len(msgs) < MAX_comments else len(msgs)
        other_msgs = self.db.query("SELECT * FROM other_messages LIMIT %s" % str(MAX_comments - len(msgs)))
        entry['msgs'] = msgs + other_msgs
        # entry['msgs'] = msgs
        comm = self.db.query("SELECT * FROM comments ORDER BY published LIMIT %s" % str(MAX_comments))
        entry['comments'] = comm
        # entry['username'] = str(htor_user['name'])
        # entry['pub'] = pathname2url(htor_user['pub'])
        self.render("entry.html", entry=entry)

    # def reply_other_messages(self, reply, slug, htor_user):
    #     #   TODO: when run with many users, comments must be more than 200
    #     MAX_comments = MIN_COMMENTS
    #     entry = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
    #     if not entry:
    #         entry = self.db.get("SELECT * FROM entries WHERE id = %s", 1)
    #     entry['pub_success'] = reply
    #
    #     other_msgs = self.db.query("SELECT * FROM other_messages LIMIT %s" % str(MAX_comments))
    #     entry['msgs'] = other_msgs
    #     comm = self.db.query("SELECT * FROM comments ORDER BY published LIMIT %s" % str(MAX_comments))
    #     entry['comments'] = comm
    #     self.render("entry.html", entry=entry)

    def get(self, slug):
        # cc_user = self.get_current_user()
        # check if htor
        # self.set_cookie('_ga', 'GA1.1.779844033.1485068018')
        # self.set_cookie('user_name', 'ggggg')
        # self.set_cookie('user_auth', '%25%21Z%2CgV6y%7B%28f9JvbW%3F%7B%234BPCf7WdxJIgr2%3F%7CE%29i%3C%23cdCkA%23%7Bl%23t')
        # self.set_cookie('user_info', '%00%BB%1F%28%E1%21%1Ee%FD%21%84%C4%FBi%BE%C4%3AX%3F%C2E%9Am%D2Y%82%A06hL%8E%B6%C8%05%D8%23%000%40%1E%5B%84n%02%89%A0x%FE%CC%B6%09%CC%12%FF%A6%B1yb%E1%10%DB%8F%DAib%7C%7E%A8%2C%8Cb%2A%AA%FCuw%A6hRs%87%3D%A4%EC%C2%A7%E0%96%90H%22%BF%AFT%B3%BB%BB%05%A7%23%1B%A8x%3Ew%B5y%16U%11%1C%EB%C5t%5E%EF%0FU%BA%1E%94%09Pj%F2%7Ef%F8%F1%E6C%10M2%2B%B4v%9E%B2%13R%D7-%9E%05%B4%C3%5By%C8%11%02%B1%F0M%3C1%3C%81%A6%7Fd%EBl%958%A8%04%C4')
        # self.set_cookie('user_info1', '%014q%BC%C1%05Rd%E8%06%F2%A1%098%7C%0A%8226%5Cl%A4%B1%B1%CBQJ%40%F6yZ%0A%F2%C1luz%C6%17%23%AC%A7%A5%A3%0D%F5%F5%EApA%B9%09%3E%98%AC%15%06%F7%C0%91pIT%C7R%23%3F%91%B1%5B%CD%A0%F1%87P%EB%1B%E1%27%CE%2C%D5B%CCJ%7E%07D%1E6%96%F7%CFYs%A5%82s%D5%5C%EB%EA%171%88%8B%83%85%16i%C2%D1%1B%3F%8D%D6%CB%29F%DB%5C%CC%DC%13z3%81d%A6%CF%E4%DA%F0%B9%F1%7Dxv%17%FB%85%AB%90%0D%95%A9%A3%0BS%C8%ECI%1A%D0%22%017%990%1F7%C1K2%12%F2d%A6%9B')
        cookies = self.cookies
        #   request start time: self.request[' _start_time']
        #   decode send_time and compare to self.request[' _start_time']
        #   create 'last_sent_time' in table authors to limit htor user send frequency.
        if '_ga' not in cookies:
            self.random_reply('bad', slug)
        if 'user_auth' not in cookies:
            uniqueId = cookies['_ga'].value.split('.')[2]
            exist = self.db.query("SELECT * FROM authors WHERE uid = %s", uniqueId)
            spr = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50))
            spub = str(seccure.passphrase_to_pubkey(spr))
            spub = pathname2url(spub)
            if not exist:
                self.db.execute(
                    "INSERT INTO authors (uid, ip, spr)"
                    "VALUES (%s, %s, %s)",
                    uniqueId, self.request.remote_ip, spr)
                self.random_reply(spub, slug)
            else:
                self.random_reply('bad', slug)
            b = 1
        else:
            # if user_auth exists, then user_info exists
            ga_cookie = cookies['_ga'].value.split('.')
            uniqueId = ga_cookie[2]
            msg_sent_time = ga_cookie[3]
            request_usr = self.db.query("SELECT * FROM authors WHERE uid = %s", uniqueId)[0]
            if not request_usr['pub']:
                # start registration completion. process user register info
                user_rinfo = url2pathname(cookies['user_info'].value)
                user_rinfo = seccure.decrypt(user_rinfo, str(request_usr['spr']))
                user_rinfo = user_rinfo.split(' ', 1)
                # hashed_pw = hashlib.sha224(user_rinfo[1]).hexdigest()
                self.db.execute("UPDATE authors SET last_message_id = %s, pub = %s \
                                WHERE uid = %s", 0, user_rinfo[1], user_rinfo[0])
                self.random_reply(user_rinfo[0], slug)
            else:
                # ready to receive a HTor message
                user_auth = url2pathname(cookies['user_auth'].value)
                secret = seccure.verify(msg_sent_time, user_auth, str(request_usr['pub']))
                print (secret)
                if not secret:
                    self.random_reply('wrong_auth_info', slug)
                    return
                # authentication received
                # check if update pub.
                if 'user_pass' in cookies:
                    # temp_new_pub = cookies['user_pass'].value
                    # user_new_pub = self.decapsulate(temp_new_pub)
                    user_new_pub = url2pathname(cookies['user_pass'].value)
                    # user_new_pub = temp_new_pub
                    # if temp_new_pub.find('eee') >= 0 or temp_new_pub.find('sss') >= 0:
                    #     user_new_pub = self.deManipulate(temp_new_pub)
                    try:
                        user_new_pub = seccure.decrypt(user_new_pub, str(request_usr['pub']))
                        self.db.execute(
                            "UPDATE authors SET pub = %s"
                            "WHERE id = %s", user_new_pub, request_usr['id'])
                        # print ('pub update success!')
                        # print ('user_new_pub:' + user_new_pub)
                        # print ('temp_new_pub:' + temp_new_pub)
                        # print ('cookie value:' + cookies['user_pass'].value)
                    except:
                        print ('pub update fail, username %s' % request_usr['name'])
                        # print ('user_new_pub:' + user_new_pub)
                        # print ('temp_new_pub:' + temp_new_pub)
                        # print ('cookie value:' + cookies['user_pass'].value)
                        return
                # get message from user_info* and store to table
                inprocess = self.not_finished(cookies, 0)
                count = 0
                while inprocess:
                    # try:
                    user_info = url2pathname(cookies[inprocess].value)
                    user_info = seccure.decrypt(user_info, str(request_usr['spr']))
                    sp = user_info.split(' ', 2)
                    # print (len(sp))
                    # message mode, user_id + sign + $E_b_pub(A_pub, message, E_a_pr(H(message)), GMT time)
                    user_id = sp[0]
                    symbol = sp[1]
                    en_message = sp[2]
                    #   X use receiver's pub to encrypt en_message/ second is encrypted, no need to encrypt again
                    # receiver_pub = self.db.query("SELECT pub FROM authors WHERE uid = %s", user_id)
                    # en_message = pathname2url(seccure.encrypt(en_message, str(receiver_pub[0]['pub'])))

                    # print en_message
                    self.db.execute(
                        "INSERT INTO messages (team_id, first_m, second_m)"
                        "VALUES (%s, %s, %s)",
                        user_id, symbol, en_message)
                    print ('success')
                    # except:
                    #     self.reply_all_messages('message_success_%s'%count, slug, htor_user)
                    count += 1
                    inprocess = self.not_finished(cookies, count)

                self.reply_all_messages('message_success', slug, request_usr)


class CommentsHandler(BaseHandler):
    def get(self, username, time, slug):
        b = 1
        print ("comments")

class ArchiveHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC")
        self.render("archive.html", entries=entries)


class FeedHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC LIMIT 10")
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
        title = self.get_argument("title")
        text = self.get_argument("markdown")
        html = markdown.markdown(text)
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
            if not entry: raise tornado.web.HTTPError(404)
            slug = entry.slug
            self.db.execute(
                "UPDATE entries SET title = %s, markdown = %s, html = %s "
                "WHERE id = %s", title, text, html, int(id))
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
                "INSERT INTO entries (author_id,title,slug,markdown,html,"
                "published) VALUES (%s,%s,%s,%s,%s,UTC_TIMESTAMP())",
                self.current_user.id, title, slug, text, html)
        self.redirect("/entry/" + slug)


class AuthCreateHandler(BaseHandler):
    def get(self):
        self.render("create_author.html")

    @gen.coroutine
    def post(self):
        # if self.any_author_exists():
        #     raise tornado.web.HTTPError(400, "author already created")
        # hashed_password = yield executor.submit(
        #     bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
        #     bcrypt.gensalt())
        hashed_password = hashlib.sha224(self.get_argument("password")).hexdigest()
        author_id = self.db.execute(
            "INSERT INTO authors (email, name, hashed_password) "
            "VALUES (%s, %s, %s)",
            self.get_argument("email"), self.get_argument("name"),
            hashed_password)
        self.set_secure_cookie("blogdemo_user", str(author_id))
        self.redirect(self.get_argument("next", "/"))


class AuthLoginHandler(BaseHandler):
    def get(self):
        # If there are no authors, redirect to the account creation page.
        if not self.any_author_exists():
            self.redirect("/auth/create")
        else:
            self.render("login.html", error=None)

    @gen.coroutine
    def post(self):
        author = self.db.get("SELECT * FROM authors WHERE email = %s",
                             self.get_argument("email"))
        if not author:
            self.render("login.html", error="email not found")
            return
        hashed_password = hashlib.sha224(self.get_argument("password")).hexdigest()
        # hashed_password = yield executor.submit(
        #     bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
        #     tornado.escape.utf8(author.hashed_password))
        if hashed_password == author.hashed_password:
            self.set_secure_cookie("blogdemo_user", str(author.id))
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html", error="incorrect password")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("blogdemo_user")
        self.redirect(self.get_argument("next", "/"))


class EntryModule(tornado.web.UIModule):
    def render(self, entry):
        return self.render_string("modules/entry.html", entry=entry)


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
