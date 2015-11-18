#!/usr/bin/env python
import web

urls = (
'/', 'index'
)

render = web.template.render('templates/')

db = web.database(dbn='postgres', user='postgres', pw='', db='editr')

class index:
    def GET(self):
        return render.index(" ")

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
