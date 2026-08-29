# -*- coding: utf-8 -*-
"""
把 docx 笔记解析为检索站所需的 JSON 数据。

用法：
    pip install python-docx
    python3 tools/parse_docx.py 抖音视频笔记.docx
    python3 tools/parse_docx.py 新文档.docx -o ./data

输出：
    data/index.json   目录与摘要（约 100 KB，首屏加载）
    data/full.json    全文与表格（约 1.3 MB，后台加载）

文档需满足的结构：
    Heading 1  -> 年份分章（目录区会自动跳过）
    Heading 2  -> 每一期的标题
    Heading 3  -> 期内小节（摘要 / 核心要点）
    正文段落 + 表格
"""
import json
import os
import re
import gzip
import argparse

try:
    import docx
    from docx.table import Table
    from docx.text.paragraph import Paragraph
    from docx.oxml.ns import qn
except ImportError:
    raise SystemExit('缺少依赖，请先执行：pip install python-docx')


def iter_block_items(parent):
    """按文档真实顺序产出段落与表格"""
    for child in parent.element.body.iterchildren():
        if child.tag == qn('w:p'):
            yield Paragraph(child, parent)
        elif child.tag == qn('w:tbl'):
            yield Table(child, parent)


def parse(src):
    d = docx.Document(src)
    blocks = list(iter_block_items(d))

    # 目录区在第一个 Heading 1 之前，正文从第一个 Heading 1 开始
    start = None
    for i, b in enumerate(blocks):
        if isinstance(b, Paragraph) and b.style.name == 'Heading 1' and b.text.strip():
            start = i
            break
    if start is None:
        raise SystemExit('未找到 Heading 1 标题，请确认文档使用了标题样式')
    print('正文起始块索引:', start)

    chapters = []
    cur_chapter = None
    cur_item = None
    cur_section = None

    def new_item(title_text):
        nonlocal cur_item, cur_section
        # 只有「期号 + 非空标题」时才拆分，避免期号与标题重复
        m = re.match(r'^\s*(第[一二三四五六七八九十百零〇\d]+期)\s+(.+)$', title_text.strip())
        if m:
            no, title = m.group(1), m.group(2).strip()
        else:
            m2 = re.match(r'^\s*(天道系列第[一二三四五六七八九十百零〇\d]+期)\s+(.+)$', title_text.strip())
            if m2:
                no, title = m2.group(1), m2.group(2).strip()
            else:
                no, title = '', title_text.strip()
        cur_item = {'no': no, 'title': title, 'meta': '', 'sections': []}
        cur_section = {'heading': '', 'blocks': []}
        cur_item['sections'].append(cur_section)
        return cur_item

    def ensure_section(heading):
        nonlocal cur_section
        cur_section = {'heading': heading, 'blocks': []}
        cur_item['sections'].append(cur_section)

    def add_block(kind, payload):
        if cur_item is None:
            return
        cur_section['blocks'].append({'t': kind, 'v': payload})

    for b in blocks[start:]:
        if isinstance(b, Paragraph):
            text = b.text.strip()
            style = b.style.name
            if not text:
                continue
            if style == 'Heading 1':
                cur_chapter = {'chapter': text, 'items': []}
                chapters.append(cur_chapter)
                cur_item = None
                continue
            if style == 'Heading 2':
                cur_chapter['items'].append(new_item(text))
                continue
            if style == 'Heading 3':
                if cur_item is None:
                    cur_chapter['items'].append(new_item(cur_chapter['chapter'] + ' · 其他'))
                ensure_section(text)
                continue
            if cur_item is None:
                cur_chapter['items'].append(new_item(cur_chapter['chapter'] + ' · 其他'))
            # 元信息行：视频时长 / 来源 / 时间
            if re.match(r'^视频时长[:：]', text) and not cur_item['meta']:
                cur_item['meta'] = text
                continue
            add_block('p', text)
        else:
            rows = [[c.text.strip() for c in r.cells] for r in b.rows]
            if rows:
                add_block('table', rows)

    # 组装：为每期生成全文检索文本和摘要
    total_chars = 0
    gseq = 0
    for ch in chapters:
        for idx, item in enumerate(ch['items']):
            item['sections'] = [s for s in item['sections'] if s['blocks'] or s['heading']]
            item['seq'] = idx + 1
            item['gseq'] = gseq
            gseq += 1

            parts = [item['no'], item['title'], item['meta']]
            summary = ''
            for sec in item['sections']:
                if sec['heading']:
                    parts.append(sec['heading'])
                for blk in sec['blocks']:
                    if blk['t'] == 'p':
                        parts.append(blk['v'])
                        if sec['heading'] in ('摘要', '概述') and not summary:
                            summary = blk['v']
                    elif blk['t'] == 'table':
                        for row in blk['v']:
                            parts.append(' '.join(row))
            item['fullText'] = '\n'.join(x for x in parts if x)

            if not summary:
                for sec in item['sections']:
                    for blk in sec['blocks']:
                        if blk['t'] == 'p' and len(blk['v']) > 20:
                            summary = blk['v']
                            break
                    if summary:
                        break
            item['summary'] = summary[:100]
            item['id'] = '%s-%03d' % (ch['chapter'], idx)
            item['chars'] = len(item['fullText'])
            total_chars += item['chars']

    return chapters, {
        'chapters': len(chapters),
        'items': sum(len(c['items']) for c in chapters),
        'chars': total_chars,
    }


def write(chapters, stats, out_dir, title='抖音视频笔记'):
    # 轻量索引：只含目录与摘要，首屏秒开
    lite = {
        'title': title,
        'stats': stats,
        'chapters': [
            {
                'chapter': ch['chapter'],
                'items': [
                    {
                        'id': it['id'], 'no': it['no'], 'title': it['title'],
                        'meta': it['meta'], 'summary': it['summary'],
                        'seq': it['seq'], 'gseq': it['gseq'], 'chars': it['chars'],
                    }
                    for it in ch['items']
                ],
            }
            for ch in chapters
        ],
    }
    # 全文：含分节内容，供检索与阅读
    fulltext = {
        'chapters': [
            {
                'chapter': ch['chapter'],
                'items': [
                    {
                        'id': it['id'], 'no': it['no'], 'title': it['title'],
                        'meta': it['meta'], 'seq': it['seq'], 'gseq': it['gseq'],
                        'sections': [{'h': s['heading'], 'b': s['blocks']} for s in it['sections']],
                    }
                    for it in ch['items']
                ],
            }
            for ch in chapters
        ],
    }

    os.makedirs(out_dir, exist_ok=True)
    for name, obj in (('index.json', lite), ('full.json', fulltext)):
        p = os.path.join(out_dir, name)
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, separators=(',', ':'))
        with open(p, 'rb') as f:
            gz = len(gzip.compress(f.read()))
        print('  %-12s %8d B   (gzip 后 %d B)' % (name, os.path.getsize(p), gz))


def main():
    ap = argparse.ArgumentParser(description='把 docx 笔记解析为检索站所需的 JSON 数据')
    ap.add_argument('src', nargs='?', default='抖音视频笔记.docx', help='输入的 .docx 文件')
    ap.add_argument('-o', '--out', default=None, help='输出目录（默认：../data）')
    ap.add_argument('-t', '--title', default='抖音视频笔记', help='站点标题')
    args = ap.parse_args()

    out_dir = args.out or os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'))

    chapters, stats = parse(args.src)
    print(json.dumps(stats, ensure_ascii=False))
    for ch in chapters:
        print('  ', ch['chapter'], len(ch['items']), '期')
    write(chapters, stats, out_dir, args.title)
    print('完成，输出目录：' + out_dir)


if __name__ == '__main__':
    main()
