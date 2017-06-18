import urllib.parse as urlparse
import ssl, socket
from contextlib import closing
import json
import os
import sys
import pickle
import time
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWidgets import QApplication, QWidget, QGridLayout, QMenu, QSystemTrayIcon
from PyQt5.QtCore import QUrl, QCoreApplication
from PyQt5.QtGui import QIcon

appSetting = {}
appSetting['client_id'] = "875631228753-kngqvtfsvqq9cbtjkrr3mqooej52uvr0.apps.googleusercontent.com"
appSetting['redirect_uri'] = "urn:ietf:wg:oauth:2.0:oob"
appSetting['scope'] = "https://www.googleapis.com/auth/youtube"  # https://developers.google.com/identity/protocols/googlescopes #"+https://mail.google.com/"
appSetting['auth_uri'] = "https://accounts.google.com/o/oauth2/auth"
appSetting['token_uri'] = "https://accounts.google.com/o/oauth2/token"
appSetting['client_secret'] = 'wTQnAhwHl7i7WESBq6Vtx4eN'

dirName = 'Nya youtube Playlist'
if sys.platform == 'win32':
    user_path = os.getenv('APPDATA')
elif sys.platform == 'linux':
    user_path = os.path.expanduser("~")
    dirName = '.' + dirName

program_path = user_path + '/' + dirName + '/'
if not os.path.exists(program_path):
    os.mkdir(program_path)

class MainWindow(QWidget):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        #self.resize(700, 400)

        self.requests = requests()

        self.OAuth20Data = {}

        self.icon = QIcon('terrible.png')
        self.setWindowIcon(self.icon)

        self.badtitle = False

        self.tray = QSystemTrayIcon(self.icon)
        self.menu = QMenu()
        quitAction = self.menu.addAction('Quit')
        quitAction.triggered.connect(QCoreApplication.instance().quit)
        self.tray.setContextMenu(self.menu)

        if not self.loadToken():
            self.show()
            OAuth20url = "?response_type=code&access_type=offline&" \
                         "client_id=" + appSetting['client_id'] + "&" \
                         "redirect_uri=" + appSetting['redirect_uri'] + "&" \
                         "scope=" + appSetting['scope']

            self.browser = QWebEngineView()
            self.browser.titleChanged['QString'].connect(self.titleLoad)
            self.browser.load(QUrl(appSetting['auth_uri'] + OAuth20url))

            self.grid = QGridLayout()
            self.grid.addWidget(self.browser, 0, 0)
            self.setLayout(self.grid)

        else:
            self.show_tray()
            #print('nya22')
            print(self.OAuth20Data['access_token'])
            self.subscriptionsGo()

    def subscriptionsGo(self):
        if not self.subscriptions():
            print('U2', 'если была ошибка, то пробуем ещё раз')
            self.subscriptions()

    def subscriptions(self):
        headers = {'Authorization': 'Bearer ' + self.OAuth20Data['access_token']}
        params = str(urlparse.urlencode({'part': 'snippet,contentDetails', 'mine': 'true'}).encode('ascii'))[2:-1]

        response = self.requests.request('GET', 'https://www.googleapis.com/youtube/v3/subscriptions?' + params, headers)
        print(response)
        err = self.responseError(response)
        print('err', err[0], err[1])
        if not err[0]:
            print('U1', 'всё ок')
            return True
        else:
            if err[1]:
                print('U3', 'была ошибка, пробуем ещё')
                return False
            else:
                print('U3', 'была ошибка, хватит')
                return True
        return True

    def responseError(self, response):
        if response['code'] == 401:
            if self.getToken():
                self.saveToken()
                print(self.OAuth20Data['access_token'])
                return True, True
        if response['code'] == 400:
            #print(json.loads(response['ResponseText']))
            print(response['ResponseText'])
            return True, False
        elif response['code'] == 200:
            return False, False


    def show_tray(self):
        #print('nya20')
        self.tray.show()

    def __del__(self):
        self.tray.hide()

    def saveToken(self):
        with open(program_path + 'token.pkl', 'wb') as token_pickle:
            pickle.dump(self.OAuth20Data, token_pickle)

    def loadToken(self):
        if os.path.exists(program_path + 'token.pkl'):
            with open(program_path + 'token.pkl', 'rb') as token_pickle:
                self.OAuth20Data = pickle.load(token_pickle)
            return True
        else:
            return False

    def titleLoad(self, title):
        if self.badtitle:
            print('Что за хрень?????')
            return
        if title.find('Success code=') != -1:
            print('Nya???????')
            self.badtitle = True
            print(title)
            self.OAuth20Data['code'] = title[13:]
            self.saveToken()
            self.browser.close()
            self.hide()
            self.show_tray()

            if self.getToken(False):
                self.saveToken()

            self.subscriptionsGo()

    def getToken(self, stage=True):
        if stage:
            params = {'grant_type': 'refresh_token', 'refresh_token': self.OAuth20Data['refresh_token']}
            print('T1')
        else:
            params = {'grant_type': 'authorization_code', 'code': self.OAuth20Data['code'], 'redirect_uri':appSetting['redirect_uri']}
            print('T2')

        params['client_id'] = appSetting['client_id']
        params['client_secret'] = appSetting['client_secret']
        params = urlparse.urlencode(params).encode('ascii')

        response = self.requests.request('POST', appSetting['token_uri'], {'Content-Type': 'application/x-www-form-urlencoded'}, params)
        ResponseDict = json.loads(response['ResponseText'])

        if response['code'] == 200:
            self.OAuth20Data['token_type'] = ResponseDict['token_type']
            self.OAuth20Data['expires_in'] = ResponseDict['expires_in']
            self.OAuth20Data['time'] = time.time()
            self.OAuth20Data['access_token'] = ResponseDict['access_token']
            if not stage:
                self.OAuth20Data['refresh_token'] = ResponseDict['refresh_token']
            return True
        else:
            return False

class requests:
    def __init__(self):
        pass

    def parseResponse(self, data):
        response = {}
        data = data.split("\\r\\n")
        response['method'], response['code'], response['status'] = data[0].split(" ", 2)
        response['code'] = int(response['code'])
        headers = {}
        for i, line in enumerate(data[1:]):
            if not line.strip():
                break
            key, value = line.split(": ", 1)
            headers[key] = value
        response['headers'] = headers
        response['ResponseText'] = data[i + 2].replace('\\n', '')

        return response

    def request(self, method, url, headers='', params=''):
        urlParse = urlparse.urlparse(url)

        if method == 'GET':
            path = urlParse.path + '?' + urlParse.query
            print(urlParse)
        elif method == 'POST':
            path = urlParse.path

        ca_certs = 'cacert.pem'
        kwargs = {}
        if os.path.exists(ca_certs):
            kwargs.update(cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLSv1, ca_certs=ca_certs)

        headersStr = ''
        for key in headers:
            headersStr += "{param}: {value}\r\n".format(param=key, value=headers[key])

        with closing(ssl.wrap_socket(socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM), **kwargs)) as s:
            s.connect((urlParse.hostname, 443))
            s.sendall("{metod} {path} HTTP/1.1\r\n"\
                      "Host: {hostname}\r\n"\
                      "Connection: close\r\n"\
                      "{headers}" \
                      "Content-Length: {len}\r\n"\
                      "\r\n".format(hostname=urlParse.hostname, len=len(params), path=path, metod=method, headers=headersStr).encode('ascii'))

            if method == 'POST':
                s.sendall(params)

            data = ''
            while True:
                buff = s.recv(512)
                if (len(buff) < 1):
                    break
                data += str(buff)[2:-1]

        return self.parseResponse(data)

if __name__ == '__main__':
        app = None
        if not QApplication.instance():
            app = QApplication([])
        dlg = MainWindow()
        if app: app.exec_()