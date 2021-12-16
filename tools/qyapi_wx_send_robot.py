#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
使用企业微信提供的Robot服务在企业微信群发送消息
"""

import os
import sys
import json
import codecs

FILE_ENCODING = 'utf-8'

NEWS_DEFAULT_TITLE = "NO TITLE"
NEWS_DEFAULT_URL = "https://owent.net"

if sys.version_info[0] == 2:

    def CmdArgsGetParser(usage):
        reload(sys)
        sys.setdefaultencoding('utf-8')
        from optparse import OptionParser
        return OptionParser('usage: %(prog)s ' + usage)

    def CmdArgsAddOption(parser, *args, **kwargs):
        parser.add_option(*args, **kwargs)

    def CmdArgsParse(parser):
        return parser.parse_args()[0]

    def SendHttpRequest(url_prefix,
                        post_body=None,
                        headers={},
                        url_suffix=None):
        import requests
        import urllib2
        if url_suffix is None:
            url = url_prefix
        else:
            url = urllib2.urlparse.urljoin(url_prefix, url_suffix)
        if post_body is None:
            rsp = requests.get(url, headers=headers, timeout=30.0)
        else:
            rsp = requests.post(url,
                                headers=headers,
                                data=post_body,
                                timeout=30.0)
        if rsp.status_code != 200:
            rsp.raise_for_status()
        else:
            return rsp.content.decode('utf-8')

else:

    def CmdArgsGetParser(usage):
        from argparse import ArgumentParser
        return ArgumentParser(usage="%(prog)s " + usage)

    def CmdArgsAddOption(parser, *args, **kwargs):
        parser.add_argument(*args, **kwargs)

    def CmdArgsParse(parser):
        return parser.parse_args()

    def SendHttpRequest(url_prefix,
                        post_body=None,
                        headers={},
                        url_suffix=None):
        import urllib.request
        import urllib.parse
        if url_suffix is None:
            url = url_prefix
        else:
            url = urllib.parse.urljoin(url_prefix, url_suffix)

        if post_body is None:
            req = urllib.request.Request(url=url, method='GET')
        else:
            req = urllib.request.Request(url=url, method='POST')

        for k in headers:
            req.add_header(k, headers[k])

        if post_body is None:
            with urllib.request.urlopen(req, 30.0) as f:
                return f.read().decode('utf-8')
        else:
            req.add_header('Content-Length', len(post_body))
            with urllib.request.urlopen(req, post_body, 30.0) as f:
                return f.read().decode('utf-8')


def ReadMessageContent(file):
    if 'stdin' == file:
        return sys.stdin.read()
    if os.path.exists(file):
        fd = codecs.open(file,
                         mode='r',
                         encoding=FILE_ENCODING,
                         errors="ignore")
        return fd.read()
    return file


def SendWXRobotRawMessage(url,
                          msg,
                          chat_id=None,
                          visible_to_user=[],
                          show_verbose=False):
    try:
        if chat_id is not None and chat_id:
            msg["chatid"] = chat_id

        if visible_to_user is not None and visible_to_user:
            msg["visible_to_user"] = '|'.join(visible_to_user)

        json_content = json.dumps(msg, indent=2)
        if show_verbose:
            print('Request with json: {0}'.format(json_content))
        response_content = SendHttpRequest(
            url,
            post_body=json_content.encode('utf-8'),
            headers={
                "Content-Type": "application/json; charset=utf-8"  #,
                #"Expect": "100-continue"
            })
        if show_verbose:
            print('Got response: {0}'.format(response_content))
        json_decoder = json.JSONDecoder(strict=False)
        return json_decoder.decode(response_content)
    except Exception as e:
        return '{0}'.format(e)


def SendWXRobotText(url,
                    text,
                    mentioned_list=[],
                    mentioned_mobile_list=[],
                    chat_id=None,
                    visible_to_user=[],
                    show_verbose=False):
    msg = {
        "msgtype": "text",
        "text": {
            "content": text,
            "mentioned_list": mentioned_list,
            "mentioned_mobile_list": mentioned_mobile_list
        }
    }
    return SendWXRobotRawMessage(url,
                                 msg,
                                 chat_id,
                                 visible_to_user,
                                 show_verbose=show_verbose)


def SendWXRobotMarkdown(url,
                        markdown,
                        chat_id=None,
                        visible_to_user=[],
                        show_verbose=False):
    msg = {"msgtype": "markdown", "markdown": {"content": markdown}}
    return SendWXRobotRawMessage(url,
                                 msg,
                                 chat_id,
                                 visible_to_user,
                                 show_verbose=show_verbose)


def SendWXRobotImage(url,
                     image_binary,
                     chat_id=None,
                     visible_to_user=[],
                     show_verbose=False):
    import base64
    import hashlib
    msg = {
        "msgtype": "image",
        "image": {
            "base64": base64.standard_b64encode(image_binary).decode('utf-8'),
            "md5": hashlib.md5(image_binary).hexdigest()
        }
    }
    return SendWXRobotRawMessage(url,
                                 msg,
                                 chat_id,
                                 visible_to_user,
                                 show_verbose=show_verbose)


def SendWXRobotNews(url,
                    news_list_array,
                    chat_id=None,
                    visible_to_user=[],
                    show_verbose=False):
    news_data = []
    if news_list_array is None or not news_list_array:
        news_data.append({
            "title": NEWS_DEFAULT_TITLE,
            "url": NEWS_DEFAULT_URL
        })
    else:
        for news_post in news_list_array:
            post_json = {"title": NEWS_DEFAULT_TITLE, "url": NEWS_DEFAULT_URL}
            if "title" in news_post:
                post_json["title"] = news_post["title"]
            if "description" in news_post:
                post_json["description"] = news_post["description"]
            if "url" in news_post:
                post_json["url"] = news_post["url"]
            if "picurl" in news_post:
                post_json["picurl"] = news_post["picurl"]
            news_data.append(news_post)

    msg = {"msgtype": "news", "news": {"articles": news_data}}
    return SendWXRobotRawMessage(url,
                                 msg,
                                 chat_id,
                                 visible_to_user,
                                 show_verbose=show_verbose)


def SendWXRobotTemplateMessage(url,
                               template_id,
                               user_data=None,
                               chat_id=None,
                               visible_to_user=[],
                               show_verbose=False):
    if user_data is None:
        user_data = {}
    msg = {
        "msgtype": "template",
        "template_id": template_id,
        "user_data": json.dumps(user_data)
    }
    return SendWXRobotRawMessage(url,
                                 msg,
                                 chat_id,
                                 visible_to_user,
                                 show_verbose=show_verbose)


if __name__ == '__main__':
    parser = CmdArgsGetParser('[options]...')
    CmdArgsAddOption(
        parser,
        "-r",
        "--robot-url",
        action="store",
        help=
        "set robot url(for example: https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=633a31f6-7f9c-4bc4-97a0-0ec1eefa589)",
        dest="robot_url",
        default=None)
    CmdArgsAddOption(
        parser,
        "-t",
        "--text",
        action="store",
        help=
        "set message text file path(文本文件内容，最长不超过2048个字节, 输入 stdin 则是从标准输入读取)",
        dest="text",
        default=None)
    CmdArgsAddOption(
        parser,
        "-m",
        "--markdown",
        action="store",
        help=
        "set message markdown file path(Markdown文件内容，最长不超过2048个字节, 输入 stdin 则是从标准输入读取)",
        dest="markdown",
        default=None)
    CmdArgsAddOption(parser,
                     "-i",
                     "--image",
                     action="store",
                     help="set image file path(图片文件地址，最大不能超过2M，支持JPG,PNG格式)",
                     dest="image",
                     default=None)
    CmdArgsAddOption(parser,
                     "--news-title",
                     action="append",
                     help="add news title",
                     dest="news_title",
                     default=[])
    CmdArgsAddOption(parser,
                     "--news-description",
                     action="append",
                     help="add news description",
                     dest="news_description",
                     default=[])
    CmdArgsAddOption(parser,
                     "--news-url",
                     action="append",
                     help="add news url",
                     dest="news_url",
                     default=[])
    CmdArgsAddOption(parser,
                     "--news-picurl",
                     action="append",
                     help="add news picurl",
                     dest="news_picurl",
                     default=[])
    CmdArgsAddOption(parser,
                     "--raw",
                     action="store",
                     help="set raw json content of robot message",
                     dest="raw",
                     default=None)
    CmdArgsAddOption(parser,
                     "--template-id",
                     action="store",
                     help="set template if of template message",
                     dest="template_id",
                     default=None)
    CmdArgsAddOption(
        parser,
        "--template-user-data",
        action="store",
        help=
        "set user data(json) of template message(Use ${user_data.varname} in template)",
        dest="template_user_data",
        default=None)
    CmdArgsAddOption(parser,
                     "-f",
                     "--file-encoding",
                     action="store",
                     help="set encoding of text file or markdown file",
                     dest="file_encoding",
                     default='utf-8')
    CmdArgsAddOption(
        parser,
        "-e",
        "--mentioned-list",
        action="append",
        help=
        "set mentioned list(userid的列表，提醒群中的指定成员(@某个成员)，@all表示提醒所有人，如果开发者获取不到userid，可以使用mentioned_mobile_list)",
        dest="mentioned_list",
        default=[])
    CmdArgsAddOption(
        parser,
        "-n",
        "--mentioned-mobile-list",
        action="append",
        help="set mentioned mobile list(手机号列表，提醒手机号对应的群成员(@某个成员)，@all表示提醒所有人)",
        dest="mentioned_mobile_list",
        default=[])
    CmdArgsAddOption(parser,
                     "-c",
                     "--chat-id",
                     action="store",
                     help="set chat id",
                     dest="chat_id",
                     default=None)
    CmdArgsAddOption(parser,
                     "--visible-to-user",
                     action="append",
                     help="set visible user list(userid的列表，仅部分人可见)",
                     dest="visible_to_user",
                     default=[])
    CmdArgsAddOption(parser,
                     "-V",
                     "--verbose",
                     action="store_true",
                     help="show verbose log",
                     dest="show_verbose",
                     default=False)
    opts = CmdArgsParse(parser)
    if opts.robot_url is None:
        print('robot-url is required\n use options -h for more details.')
        exit(1)

    has_message = False
    FILE_ENCODING = opts.file_encoding
    if opts.text is not None:
        has_message = True
        print(
            SendWXRobotText(opts.robot_url,
                            ReadMessageContent(opts.text),
                            opts.mentioned_list,
                            opts.mentioned_mobile_list,
                            chat_id=opts.chat_id,
                            visible_to_user=opts.visible_to_user,
                            show_verbose=opts.show_verbose))
    if opts.markdown is not None:
        has_message = True
        print(
            SendWXRobotMarkdown(opts.robot_url,
                                ReadMessageContent(opts.markdown),
                                chat_id=opts.chat_id,
                                visible_to_user=opts.visible_to_user,
                                show_verbose=opts.show_verbose))
    if opts.image is not None:
        has_message = True
        if not os.path.exists(opts.image):
            sys.stderr.writelines(
                ['Image file \"{0}\" not found'.format(opts.image)])
        else:
            print(
                SendWXRobotImage(opts.robot_url,
                                 open(opts.image, 'rb').read(),
                                 chat_id=opts.chat_id,
                                 visible_to_user=opts.visible_to_user,
                                 show_verbose=opts.show_verbose))

    news_count = max(len(opts.news_title), len(opts.news_description),
                     len(opts.news_url), len(opts.news_picurl))
    news_list = []
    for i in range(0, news_count):
        post = {"title": NEWS_DEFAULT_TITLE, "url": NEWS_DEFAULT_URL}
        if i < len(opts.news_title):
            post["title"] = opts.news_title[i]
        if i < len(opts.news_description):
            post["description"] = opts.news_description[i]
        if i < len(opts.news_url):
            post["url"] = opts.news_url[i]
        if i < len(opts.news_picurl):
            post["picurl"] = opts.news_picurl[i]
        news_list.append(post)

    if news_list:
        has_message = True
        print(
            SendWXRobotNews(opts.robot_url,
                            news_list,
                            chat_id=opts.chat_id,
                            visible_to_user=opts.visible_to_user,
                            show_verbose=opts.show_verbose))

    if opts.template_id is not None:
        parse_json = False
        try:
            if opts.template_user_data is not None:
                json_decoder = json.JSONDecoder(strict=False)
                template_user_data = json_decoder.decode(
                    opts.template_user_data)
            else:
                template_user_data = {}
            parse_json = True
        except Exception as e:
            sys.stderr.writelines([
                'Parse json user data failed, {0}\n{1}'.format(
                    e, opts.template_user_data)
            ])
        if parse_json:
            has_message = True
            print(
                SendWXRobotTemplateMessage(
                    opts.robot_url,
                    opts.template_id,
                    template_user_data,
                    chat_id=opts.chat_id,
                    visible_to_user=opts.visible_to_user,
                    show_verbose=opts.show_verbose))
    if opts.raw is not None:
        parse_json = None
        try:
            json_decoder = json.JSONDecoder(strict=False)
            parse_json = json_decoder.decode(opts.raw)
        except Exception as e:
            sys.stderr.writelines([
                'Parse raw json message failed, {0}\n{1}'.format(e, opts.raw)
            ])
        if parse_json is not None:
            has_message = True
            print(
                SendWXRobotRawMessage(opts.robot_url,
                                      parse_json,
                                      chat_id=opts.chat_id,
                                      visible_to_user=opts.visible_to_user,
                                      show_verbose=opts.show_verbose))

    if not has_message:
        print('no message send.')
        exit(1)
