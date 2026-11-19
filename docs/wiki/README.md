# Wiki source

These files mirror the [GitHub Wiki](https://github.com/filasik/justLogin/wiki). To publish them:

```bash
git clone https://github.com/filasik/justlogin.wiki.git
cp docs/wiki/*.md justlogin.wiki/ && rm justlogin.wiki/README.md
cd justlogin.wiki && git add -A && git commit -m "Sync wiki" && git push
```
