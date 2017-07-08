import urllib.parse as urlparse
import ssl, socket
from contextlib import closing
import json
import os
import sys
import pickle
import time
import sqlite3
from datetime import datetime, timedelta
from operator import itemgetter
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWidgets import QApplication, QWidget, QGridLayout, QMenu, QSystemTrayIcon, QTableWidget, QTableWidgetItem
from PyQt5.QtCore import QUrl, QCoreApplication, Qt
from PyQt5.QtGui import QIcon

CLIENT_SECRET_FILENAME = 'client_secret_apps.googleusercontent.com.json'

class MainWindow(QWidget):
    def __init__(self, main):
        super().__init__()

        self.main = main
        self.badtitle = False

        self.initUI()


    def initUI(self):
        self.resize(700, 400)
        self.icon = QIcon('terrible.png')
        self.setWindowIcon(self.icon)

        self.tray = QSystemTrayIcon(self.icon)
        self.menu = QMenu()
        settingsAction = self.menu.addAction('Settings')
        settingsAction.triggered.connect(self.showSettings)
        quitAction = self.menu.addAction('Quit')
        quitAction.triggered.connect(QCoreApplication.instance().quit)
        self.tray.setContextMenu(self.menu)

    def getAuth(self):
        browser = QWebEngineView()
        browser.titleChanged['QString'].connect(self.titleLoad)
        browser.load(QUrl(self.main.serviceGoogle.appSetting['auth_uri'] + self.main.serviceGoogle.OAuth20url))

        grid = QGridLayout()
        grid.addWidget(browser, 0, 0)
        self.setLayout(grid)


    def showSettings(self):
        self.tabSubscrib = QTableWidget()

        self.tabSubscrib.setColumnCount(3)
        self.tabSubscrib.setColumnWidth(0, 550)
        self.tabSubscrib.setColumnWidth(1, 20)
        self.tabSubscrib.setColumnWidth(2, 20)
        self.tabSubscrib.setHorizontalHeaderLabels(['Channel', ''])
        self.tabSubscrib.setRowCount(len(self.main.serviceGoogle.dbChannelList))

        for i, channel in enumerate(self.main.serviceGoogle.dbChannelList):
            chkBoxItem = QTableWidgetItem()
            chkBoxItem.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            if channel['addplaylist']:
                chkBoxItem.setCheckState(Qt.Checked)
            else:
                chkBoxItem.setCheckState(Qt.Unchecked)

            self.tabSubscrib.setItem(i, 0, QTableWidgetItem(channel['title']))
            self.tabSubscrib.setItem(i, 1, QTableWidgetItem(str(channel['id'])))
            self.tabSubscrib.setItem(i, 2, chkBoxItem)

        self.tabSubscrib.hideColumn(1)
        self.tabSubscrib.itemChanged.connect(self.itemChanged)

        grid = QGridLayout()
        grid.addWidget(self.tabSubscrib, 0, 0)
        self.setLayout(grid)
        self.show()


    def itemChanged(self, item):
        if item.checkState() == Qt.Checked:
            state = 1
        else:
            state = 0
        print(state, item.row(), self.tabSubscrib.item(item.row(), 1).text())

        self.main.changeAddplaylist(int(self.tabSubscrib.item(item.row(), 1).text()), state)


    def checkState(self):
        sender = self.sender()
        print(sender)


    def show_tray(self):
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


class main:
    def __init__(self):
        self.OAuth20Data = {}
        self.serviceGoogle = serviceGoogle()

        self.serviceGoogle.db = sqlite3.connect(self.serviceGoogle.user_setting_path + 'youtube.sqlite')
        self.createDB()

        app = None
        if not QApplication.instance():
            app = QApplication([])

        self.win = MainWindow(self)

        if not self.serviceGoogle.loadDataAccess():
            self.win.show()
            self.win.getAuth()

        else:
            self.win.show_tray()

            self.synchroSubscriptions()
            NewVideo = self.checkNewVideo()
            playlists = self.serviceGoogle.getData('playlists', {'part': 'snippet', 'mine': 'true', 'maxResults': 50})
            print(playlists)


        if app: app.exec_()


    def __del__(self):
        self.serviceGoogle.db.close()


    def checkNewVideo(self, sortRev=False):
        startday = datetime.now()
        startday = startday - timedelta(days=1)
        startday = startday.combine(startday.date(), startday.min.time()).replace(microsecond=0).isoformat() + 'Z'
        videoList = []

        c = self.serviceGoogle.db.cursor()
        query = '''SELECT `channelId` FROM subscriptions WHERE isDel=0 AND addplaylist=1'''
        for row in c.execute(query):
            videoList = self.serviceGoogle.getData('activities',
                                       {'part': 'contentDetails', 'channelId': row[0], 'publishedAfter': startday})

        videos = ''
        for video in videoList:
            videos += video['contentDetails']['upload']['videoId'] + ','

        videosMeta = self.serviceGoogle.getData('videos', {'part': 'snippet', 'id': videos[:-1]})
        videoIdPub = []
        for video in videosMeta:
            videoIdPub.append({'id':video['id'], 'publishedAt':video['snippet']['publishedAt']})

        videoIdPub = sorted(videoIdPub, key=itemgetter('publishedAt'), reverse=sortRev)
        return videoIdPub


    def createDB(self):
        c = self.serviceGoogle.db.cursor()
        query = '''SELECT 'table' FROM sqlite_master WHERE type=? AND name=?'''
        c.execute(query, ('table', 'subscriptions'))
        if c.fetchone() == None:
            c.execute('''CREATE TABLE subscriptions
                   (id integer PRIMARY KEY  NOT NULL,
                   title          TEXT    NOT NULL,
                   channelId      TEXT    NOT NULL,
                   description    TEXT    NOT NULL,
                   addplaylist    INT     NOT NULL DEFAULT ('1'),
                   isDel          INT     NOT NULL DEFAULT ('0'));''')
        c.close()

    def synchroSubscriptions(self):
        listSubscriptionsList = self.serviceGoogle.getData('subscriptions', {'part': 'snippet', 'mine': 'true', 'maxResults': 50})

        dbChannelList, updateChannelList = [], []
        c = self.serviceGoogle.db.cursor()
        query = '''SELECT `id`, `channelId`, `title`, `description`, `isDel` FROM subscriptions'''
        for row in c.execute(query):
            dbChannelList.append({'id': row[0], 'channelId': row[1], 'title': row[2], 'description': row[3], 'isDel':row[4]})

        for n, row in enumerate(dbChannelList):
            for i, channel in enumerate(listSubscriptionsList):
                if (channel['snippet']['resourceId']['channelId'] == row['channelId']) and (channel['snippet']['title'] == row['title']) and (channel['snippet']['description'] == row['description']):
                    listSubscriptionsList.pop(i)
                    dbChannelList[n] = True
                    break
                elif ((channel['snippet']['resourceId']['channelId'] == row['channelId']) and (channel['snippet']['title'] != row['title'])) or ((channel['snippet']['resourceId']['channelId'] == row['channelId']) and (channel['snippet']['description'] != row['description'])):
                    updateItem = listSubscriptionsList.pop(i)
                    updateItem.update({'idDB':row['id']})
                    updateChannelList.append(updateItem)
                    dbChannelList[n] = True
                    break

        commit = False
        for channel in updateChannelList:
            print('update', channel)
            query = u'''UPDATE subscriptions SET title = ?, description = ? WHERE id = ?'''
            args = (channel['snippet']['title'], channel['snippet']['description'], channel['idDB'])
            c.execute(query, args)
            commit = True

        for channel in listSubscriptionsList:
            print('new: ', channel)
            query = u'''INSERT INTO subscriptions(channelId, title, description) VALUES(?,?,?)'''
            args = (channel['snippet']['resourceId']['channelId'], channel['snippet']['title'],
                    channel['snippet']['description'])
            c.execute(query, args)
            commit = True

        for row in dbChannelList:
            if row is not True:
                print('del', row['title'])
                query = u'''DELETE FROM subscriptions WHERE id = ?'''
                c.execute(query, (row['id'], ))
                commit = True

        if commit: self.serviceGoogle.db.commit()

        query = '''SELECT `id`, `title`, `addplaylist` FROM subscriptions WHERE isDel = 0'''
        for row in c.execute(query):
            self.serviceGoogle.dbChannelList.append({'id':row[0], 'title': row[1], 'addplaylist': row[2]})

        c.close()


    def changeAddplaylist(self, id, state):
        c = self.serviceGoogle.db.cursor()
        query = u'''UPDATE subscriptions SET addplaylist = ? WHERE id = ?'''
        c.execute(query, (state, id))
        self.serviceGoogle.db.commit()
        c.close()


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

        self.db = None
        self.dbChannelList = []


    def __del__(self):
        pass


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

    def getData(self, nameAPI, params):
        response = []
        if self.checkToken():
            headers = {'Authorization': 'Bearer ' + self.OAuth20Data['access_token']}
            urlParams = urlparse.urlencode(params)
            gResponse = self.request('GET', 'https://www.googleapis.com/youtube/v3/' + nameAPI + '?' + urlParams, headers)
            err = self.responseError(gResponse)
            #print(err)

            data = json.loads(gResponse['ResponseText'])
            response = data['items']

            if 'nextPageToken' in data:
                params.update({'pageToken':data['nextPageToken']})
                response.extend(self.getData(nameAPI, params))

        return response

if __name__ == '__main__':
    main()