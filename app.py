#!/usr/bin/env python
#-*-coding: utf-8 -*-
from __future__ import unicode_literals

import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.options
import os.path
import hashlib
import binascii
import sqlite3
import bcrypt
from base64 import b64encode, b64decode
from os import urandom
from tornado.options import define, options



define("port", default=8080, help="run on the given port", type=int)

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    print ((salt+pwdhash).decode('ascii'))
    return (salt+pwdhash).decode('ascii')


def verify_password(stored_password, password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    password = password.encode()
    pwdhash = hashlib.pbkdf2_hmac('sha512',password, salt.encode('ascii'), 100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    print("Yeahbye: "+pwdhash)
    return pwdhash == stored_password

try:
        db = sqlite3.connect('userinf.sqlite')
except sqlite3.OperationalError:
        db = sqlite3.connect("userinf.sqlite")

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("user")

        
class MainHandler(BaseHandler):
    print("Running Main Handler")
    @tornado.web.authenticated
    def get(self):
        self.render('index.html')
      

class LoginHandler(BaseHandler):
    
    @tornado.gen.coroutine
    def get(self):
        incorrect = self.get_secure_cookie("incorrect")
        if incorrect and int(incorrect) > 20:
            self.write('<center>blocked</center>')
            return
        self.render('login.html')
        
    @tornado.gen.coroutine
    def post(self):
        incorrect = self.get_secure_cookie("incorrect")
        if incorrect and int(incorrect) > 20:
            self.write('<center>blocked</center>')
            return
        username = self.get_argument('username')
        password = self.get_argument('password')
        print(username)
        print(password)
        #dbconnection and fetch data
        query = db.execute("SELECT COUNT (*) FROM SS_INF WHERE SS_username=?;",(username,)).fetchone()
        if query[0] == 0:
               self.write("User not found")
        else:
                sql = db.execute("SELECT (SS_password) FROM SS_INF where SS_username = ?;",(username, )).fetchone()
                hashed_password = sql
                if verify_password (hashed_password, password):
                    self.write("logged in")
                else:
                    self.write("wrong password")

class LogoutHandler(BaseHandler):
    def get(self):
        print("Hello are u here?")
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", self.reverse_url("main")))

class SignupHandler(BaseHandler):
    def get(self):
        if self.current_user:
            self.write("already logged in")
            return
        self.render("signup.html")
    def post(self):
        if self.current_user:
            self.write("already logged in")
            return
        username=self.get_body_argument("username")
        password=self.get_body_argument("password")
        try:
            with db:
                db.execute("INSERT INTO SS_INF(SS_username,SS_password) VALUES (?,?);", (username, hash_password(password)))
        except sqlite3.IntegrityError:
            self.write("user exists")
            return
        self.write("user added")

class Application(tornado.web.Application):
    def __init__(self):
        base_dir = os.path.dirname(__file__)
        settings = {
            "cookie_secret": "bZJc2sWbQLKos6GkHn/VB9oXwQt8S0R0kRvJ5/xJ89E=",
            "login_url": "/login",
            'template_path': os.path.join(base_dir, "templates"),
            'static_path': os.path.join(base_dir, "templates/Des"),
            'debug':True,
            "xsrf_cookies": True,
           
        }
        
        tornado.web.Application.__init__(self, [
            tornado.web.url(r"/", MainHandler, name="main"),
            tornado.web.url(r'/login', LoginHandler, name="login"),
            tornado.web.url(r'/logout', LogoutHandler, name="logout"),
            tornado.web.url(r'/signup', SignupHandler, name="signup"),

        ], **settings)

def main():
    tornado.options.parse_command_line()
    Application().listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()