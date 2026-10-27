"""Refresh the theme without fetching or changing issue content.

Requires Jinja2. Run from the repository root: python tools/render_cached.py
The regular Gmeek workflow remains responsible for importing issues.
"""
from pathlib import Path
import ast
import json
import math
import re
import shutil
from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
BODY = re.compile(r'(<div class="markdown-body" id="postBody">)(.*?)(</div>\s*<div style="font-size:small;)', re.S)

def icons(source):
    match = re.search(r'var IconList=(\{.*?\});', source, re.S)
    if not match:
        raise ValueError('Missing Gmeek icons')
    return ast.literal_eval(match.group(1))

def main():
    base = json.loads((ROOT / 'blogBase.json').read_text(encoding='utf-8-sig'))
    base.update(json.loads((ROOT / 'config.json').read_text(encoding='utf-8-sig')))
    env = Environment(loader=FileSystemLoader(ROOT / 'templates'))
    i18n = {'Search': '搜索', 'switchTheme': '切换主题', 'home': '首页', 'comments': '评论', 'run': '网站运行 ', 'days': ' 天', 'Previous': '上一页', 'Next': '下一页'}
    home_icons = icons((DOCS / 'index.html').read_text(encoding='utf-8'))
    tag_icons = icons((DOCS / 'tag.html').read_text(encoding='utf-8'))
    entries = {**base['postListJson'], **base['singeListJson']}
    sources = {key: (ROOT / item['htmlDir']).read_text(encoding='utf-8') for key, item in entries.items()}
    for key, item in entries.items():
        original = sources[key]
        match = BODY.search(original)
        if not match:
            raise ValueError(f'Missing article body: {item["htmlDir"]}')
        body = match.group(2)
        context = {**base, **item, 'postBody': body, 'repoName': 'faabbi/faabbi.github.io'}
        context['postUrl'] = base['homeUrl'] + '/' + item['postUrl']
        context['highlight'] = 1 if 'css/starry-night.css' in original else (2 if '<pre class="notranslate">' in body else 0)
        if item['labels'][0] in base['singlePage']:
            context['bottomText'] = ''
        output = env.get_template('post.html').render(blogBase=context, postListJson={}, i18n=i18n, IconList=icons(original))
        assert BODY.search(output).group(2) == body, f'Article body changed: {key}'
        (ROOT / item['htmlDir']).write_text(output, encoding='utf-8')
    posts = sorted(base['postListJson'].items(), key=lambda pair: (pair[1]['top'], pair[1]['createdAt']), reverse=True)
    size = base['onePageListNum']
    page_count = math.ceil(len(posts) / size)
    for page in range(page_count):
        context = base.copy()
        context['prevUrl'] = 'disabled' if page == 0 else ('/index.html' if page == 1 else f'/page{page}.html')
        context['nextUrl'] = 'disabled' if page == page_count - 1 else f'/page{page + 2}.html'
        name = 'index.html' if page == 0 else f'page{page + 1}.html'
        output = env.get_template('plist.html').render(blogBase=context, postListJson=dict(posts[page*size:(page+1)*size]), i18n=i18n, IconList=home_icons)
        (DOCS / name).write_text(output, encoding='utf-8')
    (DOCS / 'tag.html').write_text(env.get_template('tag.html').render(blogBase=base, postListJson={}, i18n=i18n, IconList=tag_icons), encoding='utf-8')
    for kind in ('css', 'js'):
        shutil.copytree(ROOT / 'static' / kind, DOCS / kind, dirs_exist_ok=True)
    print(f'Rendered {len(posts)} articles, {len(base["singeListJson"])} standalone pages and {page_count} index pages; article HTML preserved byte for byte.')

if __name__ == '__main__':
    main()
