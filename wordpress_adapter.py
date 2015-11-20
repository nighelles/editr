from bs4 import BeautifulSoup
import requests
import io,re

def adapt_from_wordpress(url):
    # returns title, author, text
    r = requests.get(url)

    text = r.content
    soup = BeautifulSoup(text,'lxml')

    f = open("test.html",'w')

    header = soup.find_all("div",id="header")[0]
    author = header.div.h4.a.prettify()

    title = soup.title.string
    
    date = ""
    post = soup.find_all("div",class_="post")[0]
    
    for i in post.find_all(class_=re.compile("share")):
        i.decompose()
        
    text = post.prettify()

    return {'title':title,'author':author,'text':text}
    
if __name__ == "__main__":
    print adapt_from_wordpress("https://exclusivelycats.wordpress.com/2015/11/17/cats-and-coloring-no-better-combination/"
)
