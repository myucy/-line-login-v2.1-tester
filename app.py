# -*- coding: utf-8 -*-

#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.


from argparse import ArgumentParser
import json
import urllib.request
import requests

from flask import Flask, request, abort, render_template, jsonify, redirect, session

import random
import string


app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.secret_key = 'hogehoge'

# セッションのためのユニークキーの作成


def randomstate(n):
    randlst = [random.choice(string.ascii_letters + string.digits)
               for i in range(n)]
    return ''.join(randlst)

# メインページ。sessionライブラリでstate管理
@app.route('/', methods=['GET'])
def Mainpage():
    # randomstate(n)でstate長を制御
    session["state"] = randomstate(32)
    return render_template('login.html',
                           state=session["state"]
                           )

# LINEログインの認可リクエストの生成
@app.route('/login', methods=['POST'])
def authorizeReq():
    scopes = ""
    i = 0
    for key in request.form.getlist("ScopeValue"):
        if (i < 1):
            i = i + 1
            scopes = key
        else:
            scopes = scopes+" "+key
    queries = {}
    queries['response_type'] = 'code'
    queries['client_id'] = request.form['ChannelIdValue']
    queries['redirect_uri'] = request.form['redirect_uriValue']
    queries['scope'] = scopes
    queries['state'] = request.form['stateValue']
    queries['prompt'] = request.form['promptValue']
    queries['bot_prompt'] = request.form['bot_promptValue']
    queries['nonce'] = request.form['nonceValue']
    queries['max_age'] = request.form['max_ageValue']
    queries['ui_locales'] = request.form['ui_localesValue']
    authorize_url = 'https://access.line.me/oauth2/v2.1/authorize?' + \
        urllib.parse.urlencode(queries)
    return redirect(authorize_url)


@app.route('/callback', methods=['GET'])
def Callbackpage():
    state = request.args.get('state')
    error = request.args.get('error')
    code = request.args.get('code')
    # ローカルで試す場合は uri = request.base_url
    # 外部サーバで試す場合はuriにHTTTPSから始まるアドレスを指定
    uri = "コールバックURLを入力"

    error_description = request.args.get('error_description')

    # エラーハンドリングよりも先にstateの検証を行う
    expected_state = session.get('state')
    if state != expected_state:
        return "[Error] state does not match", 400


    # 認可リクエストをキャンセルした場合などのerrorの制御
    if error:
        return "[Error] Not Logined: " + error + "\n" + error_description, 400

    return render_template('callback.html',
                           code=code,
                           state=state,
                           uri=uri
                           )

# アクセストークン発行
@app.route('/accesstoken', methods=['POST'])
def accesstoken():
    postdata = json.loads(request.data)
    res_raw = requests.post("https://api.line.me/oauth2/v2.1/token",
                            headers={
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            data={
                                'grant_type':  'authorization_code',
                                'code':  postdata['code'],
                                'redirect_uri':  postdata['redirect_uri'],
                                'client_id': postdata['client_id'],
                                'client_secret':  postdata['client_secret']
                            })
    params = {
        'response_body': res_raw.json(),
        'response_status_code': res_raw.status_code
    }
    return jsonify(params)

# IDトークン発行
@app.route('/idtoken', methods=['POST'])
def idtoken():
    postdata = json.loads(request.data)
    res_raw = requests.post("https://api.line.me/oauth2/v2.1/verify",
                            headers={
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            data={
                                'id_token':  postdata['id_token'],
                                'client_id':  postdata['client_id']
                            })

    params = {
        'response_body': res_raw.json(),
        'response_status_code': res_raw.status_code
    }
    return jsonify(params)


if __name__ == "__main__":
    arg_parser = ArgumentParser(
        usage='Usage: python ' + __file__ + ' [--port <port>] [--help]'
    )
    arg_parser.add_argument('-p', '--port', type=int,
                            default=8000, help='port')
    arg_parser.add_argument('-d', '--debug', default=False, help='debug')
    options = arg_parser.parse_args()
    app.debug = True
    app.run(debug=False, port=options.port, threaded=True)
