## Text sharing, File sharing, link shortener.
### frontend and backend, easily configurable (thru editing the html files and the .py)
----------------

1. Introduction
</br>
</br>
</br>
As said above, this is a **simple & private** backend (app.py) and frontend (in /templates), which has these features:
- File Sharing (get a short link to share files, and when the link is opened it will show some information)
- Text Sharing (kind of a pastebin, it will show the text and when the text was made, again in a short link)
- URL Shortener (when hosting this, it will short an url, and give you a link, and when you open it, it will automatically redirect you to that website)

2. This is 100% **anonymous**, no one can see who created the links, etc.

3. The UI is simple.

4. This is very easily self-hostable </br> </br>
Rookie Mistake: when you self-host it, you can open it in localhost:5000, when making a file/paste/shortener don't share that localhost link, localhost is only accessible on YOUR network. - instead, u can host it with your domain. (or just use it to share files with the people on your network i guess /j)
</br>
</br>
5. This project is **COMPLETLY** open source.
</br>
</br>
6. You might need to install some pip packages, if you dont have them installed already: ```pip install Flask Werkzeug shortuuid python-dotenv```
</br>
</br>
7. Demo:
```https://cgcristi.xyz/demo.mp4```
