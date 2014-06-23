#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import re

import hmac
import random
import string
import hashlib
import time
import math

from google.appengine.ext import db

jinja_env = jinja2.Environment(autoescape=True,
                               loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__),'templates')))

class Page(db.Model):
    page_name = db.StringProperty(required=True)
    version = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params) 

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def get_current_user(user):

    if user is None:
        return None
    
    current_user = None
    cookie_string = str(user)

    if (len(cookie_string) > 0):
        # verify cookie matches expected
        uid = user.split('|')[0]
        cookie_hash = user.split('|')[1]
        expected_hash = hash_str(str(uid))
            
        query_string = "SELECT * FROM User WHERE uid = %s" % int(uid)
        results = db.GqlQuery(query_string)
        result = results.get()
        
        if result and (cookie_hash == expected_hash):
            current_user = result.username

    return current_user

def is_logged_in(user):
    if user:
        return True
    else:
        return False

def is_from_login(request):
    from_page = None
    referrer = request.environ['HTTP_REFERER'] \
        if 'HTTP_REFERER' in request.environ else  None

    if referrer:
        from_page = referrer.rsplit('/',1)[1]

    return (referrer == '/login')

def find_page(page_name, version):
    query_page_name = page_name
    if (len(page_name)==0):
        query_page_name = "ROOT"

    version_string = str(version)
    query_string = "SELECT * FROM Page WHERE page_name IN ('%s') AND version = %s ORDER BY created DESC" % (query_page_name, version_string)
    results = db.GqlQuery(query_string)
    n = results.count()
    if (n == 0):
        return None
    else:
        result = list(results)
        return result[0]

def find_page_history(page_name):
    query_page_name = page_name
    if (len(page_name)==0):
        query_page_name = "ROOT"
        
    query_string = "SELECT * FROM Page WHERE page_name IN ('%s') ORDER BY created DESC" % query_page_name
    results = db.GqlQuery(query_string)
    result = list(results)
    return result

default_wiki = """
<h1>Welcome to Capozzi wiki...</h1>
"""

class WikiPage(Handler):
    def get(self):

        # check if user is logged in
        user = self.request.cookies.get('user_id')
        current_user = get_current_user(user)
                
        # does this page exist?
        page_path = self.request.path;
        page_name = page_path.rsplit('/',1)[1]

        # check version of page to get
        page = None
        version_to_view = self.request.get('v')
        if (version_to_view):
            page = find_page(page_name, version_to_view)
        else:
            h = find_page_history(page_name)
            if h:
                page = h[0]
            
        
        if is_logged_in(current_user):
            if page:
                self.render("wiki_page_logged_in.html",user=current_user,version=page.version,page_name=page_name,content=page.content)
            else:
                self.redirect('/_edit/' + page_name)
        else:
            if page:
                self.render("wiki_page.html",page_name=page_name,content=page.content)
            else:
                p = Page(page_name="ROOT",version=0,content=default_wiki)
                p.put()
                self.redirect('/')
#                self.render("wiki_page.html",page_name="",content=default_wiki)                

class Signup(Handler):
    def get(self):
        self.response.out.write("Signup");

class Login(Handler):
    def get(self):
        self.response.out.write("Login");

class Logout(Handler):
    def get(self):
        self.response.out.write("Logout");

class EditPage(Handler):
    def get(self):
        # get the content for this page, if it exists
        page_path = self.request.path;
        page_name = page_path.rsplit('/',1)[1]

        h = find_page_history(page_name)

        # check version of page to get
        page_to_edit = None
        version_to_edit = self.request.get('v')
        if (version_to_edit):
            page_to_edit = find_page(page_name, version_to_edit)
        else:
            h = find_page_history(page_name)
            if h:
                page_to_edit = h[0]

        if not page_to_edit:
            content = ''
        else:
            content = page_to_edit.content
        
        self.render("edit_page.html",page_name=page_name,content=content);

    def post(self):
        content = self.request.get('content')
        page_path = self.request.path;
        page_name = page_path.rsplit('/',1)[1]

        h = find_page_history(page_name)

        if not h:
            query_page_name = page_name
            if len(page_name) == 0:
                query_page_name = "ROOT"
            p = Page(page_name=query_page_name,version=0,content=content)
            p.put()
        else:
            # get the most recent
            most_recent = h[0]
            updated_version = most_recent.version + 1

            # check if content has changed
            if not (content == most_recent.content):
                # add a new page with updated version
                newpage = Page(page_name=most_recent.page_name,version=updated_version,content=content)
                newpage.put()
            
        #self.response.out.write(page_name + ' --> ' + content)

        # store the data in the database if does not exist, otherwise update it
        #query_string = "SELECT * FROM Page WHERE page_name IN ('%s')" % query_page_name
        #results = db.GqlQuery(query_string)
        #n = results.count()

        
        #else:
        #    # add a content "update"
        #    result = results.get()
        #    prev_content = content
        #    prev_version = result.version
        #    updated_version = prev_version + 1
        #    newpage = Page(page_name=result.page_name,version=updated_version,content=content)
        #    newpage.put()
        # probably in memcache too at some point
        
        
        # re-direct to the view of the wiki page
        self.redirect('/' + page_name)


SECRET = "iamsosecret"

USER_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_REGEX = re.compile(r"^.{3,20}$")
EMAIL_REGEX = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s,hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if (h == make_secure_val(val)):
        return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()

    h = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s|%s' % (h,salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name,pw,salt)

def isUserValid(username):
    return USER_REGEX.match(username)
    
def isPasswordValid(password):
    return PASSWORD_REGEX.match(password)

def isEmailValid(email):
    return EMAIL_REGEX.match(email)

def create_cookie_for_uid(uid):
    return make_secure_val(str(uid))

def create_user_id():
    result = db.GqlQuery("SELECT * FROM User")
    num_users = result.count()
    uid = 2001 + num_users
    return uid

class User(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    uid = db.IntegerProperty()
    
class SignupHandler(Handler):

    def render_front(self,username="",user_error="",password_error="",verify_error="",email_error=""):
        self.render("signup_form.html",
                    username=username,
                    user_error=user_error,
                    pass_error=password_error,
                    verify_error=verify_error,
                    email_error=email_error)
                              
    def get(self):
        self.render_front()
        
    def post(self):
        user = self.request.get('username')
        passwd = self.request.get('password')
        verifypasswd = self.request.get('verify')
        email_address = self.request.get('email')

        bUserValid = isUserValid(user)
        bPasswordValid = isPasswordValid(passwd)
        bVerifyValid = (passwd == verifypasswd)

        if (email_address == ""):
            bEmailValid = True
        else:
            bEmailValid = isEmailValid(email_address)

        userError = ""
        if (not bUserValid):
            userError = "Error:  username is invalid!  (must be between 3 and 20 characters and no special symbols)"

        passError = ""
        if (not bPasswordValid):
            passError = "Error:  invalid password!"
            passwd = ""
            verifypasswd = ""

        verifyError = ""
        if (not bVerifyValid):
            verifyError = "Error:  passwords do not match!"
            passwd = ""
            verifypasswd = ""

        emailError = ""
        if (not bEmailValid):
            emailError = "Error:  not a valid email address!"
            
        bInputsValid = (bUserValid and bPasswordValid and bVerifyValid and bEmailValid)
        if (bInputsValid):
            # check if user already exists in database
            user_name_string = str(user)
            
            query_string = "SELECT * FROM User WHERE username IN ('%s')" % user_name_string
            #self.response.write(query_string)
            results = db.GqlQuery(query_string)
            n = results.count()
            #self.response.write(n)
            if (n > 0):
                userError = "Error:  username %s already exists.  Please choose another" % user_name_string 
                self.render_front("",userError)
            else:
                # create new user id
                uid = create_user_id()
                
                # create password hash
                password_hash = make_pw_hash(user_name_string,str(passwd))

                # create new user object and add to db
                new_user = User(username=user_name_string,password_hash=password_hash,uid=uid)
                new_user.put()

                # create cookie based on user identifier
                user_cookie = create_cookie_for_uid(uid)
                user_cookie_string = "user_id=%s; Path=/" % user_cookie

                self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie',user_cookie_string)
                self.redirect("/")
        else:
            self.render_front(user,userError,passError,verifyError,emailError)


class LoginHandler(Handler):
        
    def render_login(self,login_error=""):
        self.render("login_form.html",
                    login_error=login_error)

    def post(self):
        user = self.request.get('username')
        passwd = self.request.get('password')

        user_name_string = str(user)
            
        query_string = "SELECT * FROM User WHERE username IN ('%s')" % user_name_string
        results = db.GqlQuery(query_string)
        n = results.count()
        result = results.get()
        if result and valid_pw(str(user),str(passwd),result.password_hash):
            # create cookie based on user identifier
            user_cookie = create_cookie_for_uid(result.uid)
            user_cookie_string = "user_id=%s; Path=/" % user_cookie
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header('Set-Cookie',user_cookie_string)

            self.redirect('/')
            
        else:
            self.render_login("Invalid login!")
        
    def get(self):
        self.render_login()
        

class LogoutHandler(Handler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header('Set-Cookie','user_id=''; Path=/')

        referer = self.request.environ['HTTP_REFERER'] \
              if 'HTTP_REFERER' in self.request.environ else  None

        
        page_name = ''
        if referer:
            page_path = referer
            page_name = page_path.rsplit('/',1)[1]

        self.redirect('/' + page_name)



class HistoryHandler(Handler):
    
    def get(self):
        page_path = self.request.path;
        page_name = page_path.rsplit('/',1)[1]

        user = self.request.cookies.get('user_id')
        current_user = get_current_user(user)
        
        h = find_page_history(page_name)

        self.render("page_history.html",user=current_user,page_name=page_name,history=h)

PAGE_RE = r'/(?:\w+/?)*'
DEBUG = True
app = webapp2.WSGIApplication([('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/signup', SignupHandler),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryHandler),
                               (PAGE_RE, WikiPage)],
                              debug=DEBUG)
                               
