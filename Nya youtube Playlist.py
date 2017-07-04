import urllib.parse as urlparse
import ssl, socket
from contextlib import closing
import json
import os
import sys
import pickle
import time, datetime
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWidgets import QApplication, QWidget, QGridLayout, QMenu, QSystemTrayIcon, QTableWidget, QTableWidgetItem
from PyQt5.QtCore import QUrl, QCoreApplication, Qt
from PyQt5.QtGui import QIcon

CLIENT_SECRET_FILENAME = 'client_secret_apps.googleusercontent.com.json'

class MainWindow(QWidget):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        self.resize(700, 400)

        self.OAuth20Data = {}
        self.serviceGoogle = serviceGoogle()

        self.icon = QIcon('terrible.png')
        self.setWindowIcon(self.icon)

        self.badtitle = False

        self.tray = QSystemTrayIcon(self.icon)
        self.menu = QMenu()
        settingsAction = self.menu.addAction('Settings')
        settingsAction.triggered.connect(self.showSettings)
        quitAction = self.menu.addAction('Quit')
        quitAction.triggered.connect(QCoreApplication.instance().quit)

        self.tray.setContextMenu(self.menu)

        if not self.serviceGoogle.loadDataAccess():
            self.show()

            browser = QWebEngineView()
            browser.titleChanged['QString'].connect(self.titleLoad)
            browser.load(QUrl(self.serviceGoogle.appSetting['auth_uri'] + self.serviceGoogle.OAuth20url))

            grid = QGridLayout()
            grid.addWidget(browser, 0, 0)
            self.setLayout(grid)
        else:
            self.show_tray()
            #print(self.serviceGoogle.OAuth20Data)
            self.listSubscriptionsList = self.subscriptionsList()

            for i, channel in enumerate(self.listSubscriptionsList):
                activ = self.activitiesList(channel['snippet']['resourceId']['channelId'])
                print(activ)
                break

    def subscriptionsList(self, params={}, subscriptionsItem=[]):
        response = False
        if self.serviceGoogle.checkToken():
            headers = {'Authorization': 'Bearer ' + self.serviceGoogle.OAuth20Data['access_token']}
            params.update({'part': 'snippet,contentDetails', 'mine': 'true', 'maxResults': 50})
            params = urlparse.urlencode(params)
            response = self.serviceGoogle.request('GET', 'https://www.googleapis.com/youtube/v3/subscriptions?' + params, headers)
            err = self.responseError(response)
            #print(err)

            subscriptionsList = json.loads(response['ResponseText'])
            subscriptionsItem.extend(subscriptionsList['items'])
            response = subscriptionsItem

            if 'nextPageToken' in subscriptionsList:
                self.subscriptionsList({'pageToken':subscriptionsList['nextPageToken']}, subscriptionsItem)

        return response

    def activitiesList(self, channelId, params={}, activitiesItem=[]):
        response = False
        if self.serviceGoogle.checkToken():
            headers = {'Authorization': 'Bearer ' + self.serviceGoogle.OAuth20Data['access_token']}
            startday = datetime.datetime.now()
            startday = startday - datetime.timedelta(days=1)
            startday = startday.combine(startday.date(), startday.min.time()).replace(microsecond=0).isoformat() + 'Z'
            #print('startday: ', startday)
            params.update({'part': 'contentDetails', 'channelId': channelId, 'publishedAfter':startday})
            params = urlparse.urlencode(params) #publishedBefore

            response = self.serviceGoogle.request('GET', 'https://www.googleapis.com/youtube/v3/activities?' + params, headers)
            err = self.responseError(response)
            print(err)

            activitiesList = json.loads(response['ResponseText'])
            activitiesItem.extend(activitiesList['items'])
            response = activitiesItem

            if 'nextPageToken' in activitiesList:
                self.activitiesList({'pageToken':activitiesList['nextPageToken']}, activitiesItem)

        return response

    def showSettings(self):
        tabSubscrib = QTableWidget()

        tabSubscrib.setColumnCount(2)
        tabSubscrib.setColumnWidth(0, 550)
        tabSubscrib.setColumnWidth(1, 20)
        tabSubscrib.setHorizontalHeaderLabels(['Channel', ''])
        tabSubscrib.setRowCount(len(self.listSubscriptionsList))

        for i, channel in enumerate(self.listSubscriptionsList):
            chkBoxItem = QTableWidgetItem()
            chkBoxItem.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            chkBoxItem.setCheckState(Qt.Checked)

            tabSubscrib.setItem(i, 0, QTableWidgetItem(channel['snippet']['title']))
            tabSubscrib.setItem(i, 1, chkBoxItem)

        grid = QGridLayout()
        grid.addWidget(tabSubscrib, 0, 0)
        self.setLayout(grid)
        self.show()


    def responseError(self, response):
        if response['code'] == 401:
            if self.getToken():
                self.saveToken()
                print(self.serviceGoogle.OAuth20Data['access_token'])
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

    def titleLoad(self, title):
        if self.badtitle:
            print('Что за хрень?????')
            return
        if title.find('Success code=') != -1:
            print('Nya???????')
            self.badtitle = True
            self.serviceGoogle.OAuth20Data['code'] = title[13:]
            self.serviceGoogle.saveDataAccess()
            self.browser.close()
            self.hide()
            self.show_tray()

            self.serviceGoogle.getToken(False)

            subscriptionsList = self.subscriptionsList()
            print('Total subscriptions: ', len(subscriptionsList))

class serviceGoogle:
    def __init__(self):
        with open(CLIENT_SECRET_FILENAME, 'rb') as client_secret:
            self.appSetting = json.load(client_secret)

        self.appSetting = self.appSetting['installed']
        self.appSetting['scope'] = "https://www.googleapis.com/auth/youtube"

        self.OAuth20Data = {}
        self.OAuth20url = "?response_type=code&access_type=offline&" \
                     "client_id=" + self.appSetting['client_id'] + "&" \
                     "redirect_uri=" + self.appSetting['redirect_uris'][0] + "&" \
                     "scope=" + self.appSetting['scope']

        dirName = 'Nya youtube Playlist'
        if sys.platform == 'win32':
            user_path = os.getenv('APPDATA')
        elif sys.platform == 'linux':
            user_path = os.path.expanduser("~")
            dirName = '.' + dirName

        self.user_setting_path = user_path + '/' + dirName + '/'
        if not os.path.exists(self.user_setting_path):
            os.mkdir(self.user_setting_path)

    def checkToken(self):
        tokenLiveTime = (self.OAuth20Data['expires_in'] - self.OAuth20Data['expires_in'] * .1)
        timeNow = time.time()
        if tokenLiveTime + self.OAuth20Data['time'] < timeNow:
            return self.getToken()
        else:
            return True

    def loadDataAccess(self):
        if os.path.exists(self.user_setting_path + 'token.pkl'):
            with open(self.user_setting_path + 'token.pkl', 'rb') as token_pickle:
                self.OAuth20Data = pickle.load(token_pickle)
            return True
        else:
            return False

    def saveDataAccess(self):
        with open(self.user_setting_path + 'token.pkl', 'wb') as token_pickle:
            pickle.dump(self.OAuth20Data, token_pickle)

    def getToken(self, stage=True):
        if stage:
            params = {'grant_type': 'refresh_token', 'refresh_token': self.OAuth20Data['refresh_token']}
            print('T1')
        else:
            params = {'grant_type': 'authorization_code', 'code': self.OAuth20Data['code'],
                        'redirect_uri': self.appSetting['redirect_uri']}
            print('T2')

        params['client_id'] = self.appSetting['client_id']
        params['client_secret'] = self.appSetting['client_secret']
        params = urlparse.urlencode(params).encode('ascii')

        response = self.request('POST', self.appSetting['token_uri'],
                                             {'Content-Type': 'application/x-www-form-urlencoded'}, params)
        ResponseDict = json.loads(response['ResponseText'])

        result = False
        if response['code'] == 200:
            self.OAuth20Data['token_type'] = ResponseDict['token_type']
            self.OAuth20Data['expires_in'] = ResponseDict['expires_in']
            self.OAuth20Data['time'] = time.time()
            self.OAuth20Data['access_token'] = ResponseDict['access_token']
            if not stage:
                self.OAuth20Data['refresh_token'] = ResponseDict['refresh_token']
            self.saveDataAccess()
            result = True
        return result


    def parseResponse(self, data):
        response = {}
        data = data.split("\r\n")
        response['method'], response['code'], response['status'] = data[0].split(" ", 2)
        response['code'] = int(response['code'])
        headers = {}

        for i, line in enumerate(data[1:]):
            if not line.strip():
                break
            key, value = line.split(": ", 1)
            headers[key] = value
        response['headers'] = headers
        response['ResponseText'] = data[i + 2]

        return response

    def request(self, method, url, headers='', params=''):
        urlParse = urlparse.urlparse(url)
        if method == 'GET':
            path = urlParse.path + '?' + urlParse.query
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
                      "\r\n".format(hostname=urlParse.hostname, len=len(params), path=path, metod=method, headers=headersStr).encode('utf8'))

            if method == 'POST':
                s.sendall(params)

            data = b''
            while True:
                buff = s.recv(512)
                if (len(buff) < 1):
                    break
                data += buff

        return self.parseResponse(data.decode('utf8'))

if __name__ == '__main__':
    app = None
    if not QApplication.instance():
        app = QApplication([])
    dlg = MainWindow()
    if app: app.exec_()