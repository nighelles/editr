#!/usr/bin/env python
import web
from web import form
import bcrypt

import tempfile

import wordpress_adapter

urls = (
'/', 'index',
'/login/', 'login',
'/logout/', 'logout',
'/user/(.+)', 'user',
'/edit/post/(.+)', 'editpost',
'/delete/post/(.+)', 'delpost',
'/edit/inclusion/(.+)', 'editinclusion',
'/post/(.+)', 'viewpost'    
)

render = web.template.render('templates/')

db = web.database(dbn='postgres', user='postgres', pw='', db='editr')

postform = form.Form(
    form.Textbox("post_title", form.notnull, description="title"),
    form.Textarea("post_body", form.notnull, description="text"),
    form.Dropdown("post_layout", [(0,"Full Column"), (1,"Half Column")])
)


loginform = form.Form(
            form.Textbox("login_username",
                         form.notnull, description="username"),
            form.Password("login_password",
                         form.notnull,description="password"))

registerform = form.Form(
            form.Textbox("register_email",
                         form.notnull,description="email"),
            form.Textbox("register_username",
                         form.notnull, description="username"),
            form.Password("register_password",
                         form.notnull, description="password"),
            form.Password("register_password2",
                          form.notnull, description="password"),
            validators = [
                form.Validator("Passwords did not match", lambda i: i.register_password==i.register_password2)
            ]
)

inclusionform = form.Form(
    form.Textbox("wordpress_url",form.notnull,description="Wordpress URL"),
    form.Dropdown("wordpress_inc_type",[(0, "Full Article"), (1, "Summary and Link")])
)

def generate_session_key(username):
    session_key=""
    while True:
        session_key=bcrypt.gensalt()
        session_key=session_key[8:]
        if db.select('sessions',where="session_id="+web.db.sqlquote(session_key)).first()==None:
            break
    db.delete('sessions',where="username=$username",vars=locals())
    db.insert('sessions',username=username,session_id=session_key)

    return session_key


def check_session_key(username, session_key):
    valid_key = db.select('sessions', where="username="+web.db.sqlquote(username)).first()
    if valid_key.session_id.strip() == session_key.strip():
        return True
    else:
        return False


def logged_in_as():
    username = web.cookies().get('username')
    sessionkey = web.cookies().get('session')
    if (username is None) or (sessionkey is None):
        return None
    if (check_session_key(username, sessionkey)):
        return username
    return None


def logged_in():
    return web.cookies().get('username')!=None


def userid_from_username(username):
    u = db.select('users',where="username=$username",vars=locals()).first()
    return u.id

def username_from_userid(userid):
    u = db.select('users',where="id=$userid",vars=locals()).first()
    return u.username

def add_from_wordpress(username,uid,url):
    i = db.select('inclusions',where="url=$url",vars=locals()).first()
    if i==None:
        res = wordpress_adapter.adapt_from_wordpress(url)
        db.insert('inclusions',
                  author=res['author'],
                  title=res['title'],
                  text=res['text'],
                  url=url)
        i = db.select('inclusions',where="url=$url",vars=locals()).first()

    db.insert('posts',
              author_id=uid,
              inclusion_id=i.id,
              inclusion_type=2
    )

def add_from_editr(username,uid,postnum):
    i = db.select('posts',where="id=$postnum",vars=locals()).first()
    if i==None:
        return False
    db.insert('posts',
              author_id=uid,
              inclusion_id=postnum,
              inclusion_type=1)
        

class index:
    def GET(self):
        uname = web.cookies().get('username')
        li = logged_in()

        posts = list(db.select('posts',where="inclusion_type=0",order="date DESC",limit=20))
        #ugly hack, I'll fix tomorrow
        for i in range(0,len(posts)):
            posts[i].author = username_from_userid(posts[i].author_id)

        return render.site_header(render.index_page(posts,uname,li),li,uname)


class user:
    def GET(self,username):
        aid = userid_from_username(username)
        posts = db.select('posts',
                          where="author_id=$aid",
                          order="date DESC",
                          vars=locals())

        li = logged_in()
        mypage=False
        uname=logged_in_as()
        if li and uname==username:
            mypage=True

        posts_to_render = []
        for post in list(posts):
            if post.inclusion_type == 0:
                posts_to_render.append(post)
            elif post.inclusion_type==1:
                #This is an included editr post
                o_post = db.select('posts',where="id=$post.inclusion_id",vars=locals()).first()
                o_post.layout_type=post.layout_type
                o_post.id=post.id
                o_post.author = username_from_userid(o_post.author_id)
                o_post.edited=post.edited
                o_post.inclusion_type=1
                posts_to_render.append(o_post)
            else:
                o_post = db.select(
                    'inclusions',
                    where="id=$post.inclusion_id",
                    vars=locals()).first()
                o_post.layout_type=post.layout_type
                o_post.id=post.id
                o_post.inclusion_type=2
                o_post.edited=post.edited
                posts_to_render.append(o_post)
                
        return render.site_header(render.user_page(posts_to_render,[], username, mypage,li), li,uname)

class viewpost:
    def GET(self, postnum):
        li = logged_in()
        mypage=False
        uname=logged_in_as()

        post = db.select('posts',where="id=$postnum",vars=locals()).first()
        if post==None:
            return "Error"
        else:
            comments = db.select('comments',where="post=$postnum",vars=locals())

            owner = username_from_userid(post.author_id)
            
            return render.site_header(render.post_page(post,comments,uname,owner),li,uname)

    def POST(self, postnum):
        li = logged_in()
        mypage=False
        uname=logged_in_as()

        post = db.select('posts',where="id=$postnum",vars=locals()).first()
        if post==None:
            return "Error"
        else:
            if li:
                comment_data=web.input()
                db.insert('comments',
                          username=uname,
                          body=comment_data['comment_body'],
                          post=postnum)
                raise web.seeother("/post/"+postnum)
            else:
                return "Not logged in"
        
    
class delpost:
    def POST(self, postnum):
        uname = logged_in_as()
        if uname is None:
             return "Error"

        uid = userid_from_username(uname)
        db.delete('posts',
                    where="id=$postnum AND author_id=$uid",vars=locals())

        raise web.seeother('/user/'+uname)


class editpost:
    def GET(self, postnum):
        pform = postform()

        if postnum != 'new':
            post = db.select('posts', where="id=$postnum", vars=locals()).first()
            pform.post_title.value = post.title
            pform.post_body.value = post.text
	    pform.post_layout.value = post.layout_type

        return render.site_header(render.edit_post(pform,postnum),logged_in(),logged_in_as())

    def POST(self, postnum):
        uname = logged_in_as()
        if uname is None:
             return "Error"

        uid = userid_from_username(uname)

        pform = postform()
        if pform.validates():
            if postnum == 'new':
                db.insert('posts',
                          title=pform.post_title.value,
                          text=pform.post_body.value,
                          author_id=uid,
                          layout_type=pform.post_layout.value)
            else:
                db.update('posts',
                          title=pform.post_title.value,
                          text=pform.post_body.value,
                          layout_type=pform.post_layout.value,
                          edited=1,
                          where="id=$postnum AND author_id=$uid",
                          vars=locals())

            raise web.seeother('/user/'+uname)

        else:
            return render.site_header(render.edit_post(pform,postnum),logged_in(),uname)

class editinclusion:
    def GET(self, postnum):
        iform = inclusionform()

        if postnum != 'new':
            return "Error"

        return render.site_header(render.edit_inclusion(iform),logged_in(),logged_in_as())

    def POST(self,postnum):
        uname = logged_in_as()
        if uname is None:
            return "No Username"
        uid = userid_from_username(uname)

        iform = inclusionform()
        if postnum=='new':
            if iform.validates():
                i=web.input()
                if i['type']=="wordpress":
                    add_from_wordpress(uname,uid,iform.wordpress_url.value)
                    raise web.seeother('/user/'+uname)
                else:
                    return "Error"
            else:
                return render.site_header(render.edit_inclusion(iform),logged_in(),uname)
        else:
            #we're including a post from editr
            add_from_editr(uname,uid,postnum)
            raise web.seeother("/user/"+uname)
                
class logout:
    def GET(self):
        u = web.cookies().get('username')
        web.setcookie('username','logout',expires=-1)
        web.setcookie('session','logout',expires=-1)
        db.delete('sessions',where="username=$u",vars=locals())

        raise web.seeother('/')

class login:
    def GET(self):
        lform = loginform()
        rform = registerform()
        return render.site_header(render.login_form(lform,rform))

    def do_login(self,username,password):
        u = db.select('users',where="username="+web.db.sqlquote(username),what="password")
        passhashed = u[0].password
        if bcrypt.hashpw(password.encode('utf-8'),passhashed.encode('utf-8'))==passhashed:
            web.setcookie('username',username,3600*24)
            web.setcookie('session',generate_session_key(username))
            raise web.seeother("/")
        else:
            return "Incorrect Password"

    def do_register(self,email,username,passoword):

        return render.site_header(render.register_landing())

    def POST(self):
        lform = loginform()
        rform = registerform()
        if lform.validates():
            return self.do_login(lform.login_username.value,lform.login_password.value)
        elif rform.validates():

            return self.do_register(rform.register_email,
                                    rform.register_username,
                                    rform.register_password)
        else:
            return render.site_header(render.login_form(lform,rform))

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
