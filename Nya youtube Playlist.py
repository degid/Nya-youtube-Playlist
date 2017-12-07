import urllib.parse as urlparse
import ssl, socket
from contextlib import closing
import json
import os
import sys
import _pickle as pickle
import time
import sqlite3
from datetime import datetime, timedelta
from operator import itemgetter
from itertools import zip_longest

from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile
from PyQt5.QtWidgets import QApplication, QWidget, QGridLayout, QMenu, QSystemTrayIcon, QTableWidget, QTableWidgetItem
from PyQt5.QtCore import QUrl, QCoreApplication, Qt
from PyQt5.QtGui import QIcon

CLIENT_SECRET_FILENAME = 'client_secret_apps.googleusercontent.com.json'
DEBUG = True
MAX_DAY = 1
TIMEOUT = .5


class MainWindow(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.initUI()


    def initUI(self):
        self.resize(500, 600)
        self.icon = QIcon('terrible.png')
        self.setWindowIcon(self.icon)

        self.tray = QSystemTrayIcon(self.icon)
        self.menu = QMenu()
        settingsAction = self.menu.addAction('Run')
        settingsAction.triggered.connect(self.main.run)
        settingsAction = self.menu.addAction('Settings')
        settingsAction.triggered.connect(self.showSettings)
        quitAction = self.menu.addAction('Quit')
        quitAction.triggered.connect(QCoreApplication.instance().quit)
        self.tray.setContextMenu(self.menu)

        self.grid = QGridLayout()

    def getAuth(self):
        QWebEngineProfile.defaultProfile().setCachePath(self.main.serviceGoogle.user_setting_path)
        QWebEngineProfile.defaultProfile().setPersistentStoragePath(self.main.serviceGoogle.user_setting_path + 'Storage')

        self.browser = QWebEngineView()
        self.browser.titleChanged['QString'].connect(self.titleLoad)
        self.browser.load(QUrl(self.main.serviceGoogle.appSetting['auth_uri'] + self.main.serviceGoogle.OAuth20url))

        self.grid.addWidget(self.browser, 0, 0)
        self.setLayout(self.grid)


    def showSettings(self):
        self.tabSubscrib = QTableWidget()

        self.tabSubscrib.setColumnCount(3)
        self.tabSubscrib.setColumnWidth(0, 300)
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

        self.grid.addWidget(self.tabSubscrib, 0, 0)
        self.setLayout(self.grid)
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


    def show_tray(self):
        self.tray.show()


    def __del__(self):
        self.tray.hide()


    def titleLoad(self, title):
        if title.find('Success code=') != -1:
            self.main.serviceGoogle.OAuth20Data['code'] = title[13:]
            self.main.serviceGoogle.saveDataAccess()

            self.hide()
            self.main.reWin()


class main:
    def __init__(self):
        self.OAuth20Data = {}
        self.serviceGoogle = serviceGoogle()

        self.serviceGoogle.db = sqlite3.connect(self.serviceGoogle.user_setting_path + 'youtube.sqlite')
        self.createDB()

        self.app = None
        if not QApplication.instance():
            self.app = QApplication([])

        self.win = MainWindow(self)

        if not self.serviceGoogle.loadDataAccess():
            self.win.show()
            self.win.getAuth()

        else:
            self.win.show_tray()
            self.run()

        if self.app: result = self.app.exec_()


    def reWin(self):
        # https://bugreports.qt.io/browse/QTBUG-57228
        del self.win
        self.win = MainWindow(self)
        self.win.show_tray()
        self.run()


    def run(self):
        if 'lastRun' in self.serviceGoogle.OAuth20Data: print(self.serviceGoogle.OAuth20Data['lastRun'])
        if 'lastRun' in self.serviceGoogle.OAuth20Data: print(datetime.now()-timedelta(days=MAX_DAY))
        self.synchroSubscriptions()
        NewVideo = self.GetNewVideo()
        self.addVideoPlaylist(NewVideo)


    def __del__(self):
        self.serviceGoogle.db.close()


    def addVideoPlaylist(self, idVideos):
        startday = datetime.now()
        playlists = self.serviceGoogle.getData('playlists', {'part': 'snippet', 'mine': 'true', 'maxResults': 50})

        idPlayList = None
        for item in playlists:
            if item['snippet']['title'] == 'Auto ' + startday.date().isoformat():
                idPlayList =  item['id']
                break

        newPlaylist = False
        if idPlayList is None:
            headers = {'Authorization': 'Bearer ' + self.serviceGoogle.OAuth20Data['access_token'], 'Content-Type': 'application/json;charset=UTF-8'}
            params = {"snippet":{"title": 'Auto ' + startday.date().isoformat()},"status":{"privacyStatus": "private"}}

            response = self.serviceGoogle.request('POST', 'https://www.googleapis.com/youtube/v3/playlists?part=snippet%2Cstatus', headers, json.dumps(params).encode('utf8'))
            err = self.serviceGoogle.responseError(response)
            response = json.loads(response['ResponseText'])

            idPlayList = response['id']
            newPlaylist = True

        if not newPlaylist:
            playlistItems = self.serviceGoogle.getData('playlistItems', {'part': 'snippet', 'playlistId': idPlayList, 'maxResults': 50})
            print('Already exists in the playlist:', len(playlistItems), 'videos')
            for item in playlistItems:
                if item['snippet']['resourceId']['videoId'] in idVideos:
                    idVideos.remove(item['snippet']['resourceId']['videoId'])

        no_added = []
        for video in idVideos:
            headers = {'Authorization': 'Bearer ' + self.serviceGoogle.OAuth20Data['access_token'],
                       'Content-Type': 'application/json;charset=UTF-8'}
            params = {"snippet": {"playlistId": idPlayList,"resourceId":{"videoId": video, "kind": "youtube#video"}}}
            response = self.serviceGoogle.request('POST', 'https://www.googleapis.com/youtube/v3/playlistItems?part=snippet', headers, json.dumps(params).encode('utf8'))
            err = self.serviceGoogle.responseError(response)
            if True in err:
                time.sleep(60*2)
                response = self.serviceGoogle.request('POST',
                                                      'https://www.googleapis.com/youtube/v3/playlistItems?part=snippet',
                                                      headers, json.dumps(params).encode('utf8'))
                err = self.serviceGoogle.responseError(response)
                if True in err:
                    no_added.append(video)
                else:
                    print('readded...')

            time.sleep(TIMEOUT)

        if idVideos:
            print('Add video in playlist "%s": %d' % ('Auto ' + startday.date().isoformat(), len(idVideos)))
        else:
            print('No new videos')

        if no_added:
            print(no_added)


    def GetNewVideo(self, sortRev=False):
        if not 'lastRun' in self.serviceGoogle.OAuth20Data:
            startday = datetime.now()
            startday = startday - timedelta(days=MAX_DAY)
            startday = startday.combine(startday.date(), startday.min.time()).replace(microsecond=0).isoformat() + 'Z'
            self.serviceGoogle.OAuth20Data['lastRun'] = startday

        videoList = []
        c = self.serviceGoogle.db.cursor()
        query = '''SELECT `channelId` FROM subscriptions WHERE isDel=0 AND addplaylist=1'''
        for row in c.execute(query):
            videoList.extend(self.serviceGoogle.getData('activities',
                                       {'part': 'contentDetails', 'channelId': row[0], 'publishedAfter': self.serviceGoogle.OAuth20Data['lastRun']}))
            print('channelId:', row[0], '| Total new videos:', len(videoList))
            time.sleep(TIMEOUT)

        self.serviceGoogle.OAuth20Data['lastRun'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
        self.serviceGoogle.saveDataAccess()
        print(self.serviceGoogle.OAuth20Data['lastRun'])

        videos = []
        for video in videoList:
            if 'upload' in video['contentDetails']:
                videos.append(video['contentDetails']['upload']['videoId'])
                if DEBUG: print('upload', video['contentDetails']['upload']['videoId'])

            elif 'playlistItem' in video['contentDetails']:
                videos.append(video['contentDetails']['playlistItem']['resourceId']['videoId'])
                if DEBUG: print('playlistItem', video['contentDetails']['playlistItem']['resourceId']['videoId'])

            elif 'like' in video['contentDetails']:
                videos.append(video['contentDetails']['like']['resourceId']['videoId'])
                if DEBUG: print('like', video['contentDetails']['like']['resourceId']['videoId'])

            elif 'subscription' in video['contentDetails']:
                if DEBUG: print('subscription channelId', video['contentDetails']['subscription']['resourceId']['channelId'])

            elif 'bulletin' in video['contentDetails']:
                videos.append(video['contentDetails']['bulletin']['resourceId']['videoId'])
                if DEBUG: print('bulletin', video['contentDetails']['bulletin']['resourceId']['videoId'])

            else:
                print(video)

        print('==========================================================')

        videos = [e for i, e in enumerate(videos) if e not in videos[:i]]

        partVideos = partList(videos, 15)
        print(len(partVideos), partVideos)
        print('==========================================================')
        videosInfo = []
        for i, partVideo in enumerate(partVideos):
            videosString = ', '.join(partVideo)
            print(videosString)
            response = self.serviceGoogle.getData('videos', {'part': 'snippet', 'id': videosString})
            videosInfo.extend(response)
            time.sleep(TIMEOUT)

        videoIdPub = []
        for video in videosInfo:
            videoIdPub.append({'id':video['id'], 'publishedAt':video['snippet']['publishedAt']})

        videoIdPub = sorted(videoIdPub, key=itemgetter('publishedAt'), reverse=sortRev)

        for i, video in enumerate(videoIdPub):
            videoIdPub[i] = video['id']

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
        listSubscriptionsList = self.serviceGoogle.getData('subscriptions', {'part': 'snippet', 'mine': 'true', 'maxResults': 25})
        print('len listSubscriptionsList: ', len(listSubscriptionsList))
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
        if 'expires_in' is not self.OAuth20Data:
            self.getToken(False)

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
        else:
            params = {'grant_type': 'authorization_code', 'code': self.OAuth20Data['code'],
                        'redirect_uri': self.appSetting['redirect_uris'][0]}

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
        elif response['code'] == 400:
            #print(json.loads(response['ResponseText']))
            print(response['ResponseText'])
            return True, False
        elif response['code'] == 200:
            return False, False
        elif response['code'] == 403:
            data = json.loads(response['ResponseText'])
            if data['error']['errors'][0]['reason'] == 'quotaExceeded':
                print(data['error']['message'])
                return True, True
        else:
            print(response['ResponseText'])
            return True, True


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
        path = urlParse.path + '?' + urlParse.query


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

            # if 'subscriptions' == nameAPI:
            #     print('1', len(response))
            #     print(data)

            if 'nextPageToken' in data:
                params.update({'pageToken':data['nextPageToken']})
                response.extend(self.getData(nameAPI, params))
                # if 'subscriptions' == nameAPI:
                #     print('2', len(response))
                #     print(data)

            # if 'subscriptions' == nameAPI:
            #     print('3', len(data), params)

        return response


def partList(longList, listLen):
    iterpart = [iter(longList)] * listLen
    listParts = []
    for row in zip_longest(*iterpart, fillvalue=None):
        listParts.append(row)

    if None in listParts[-1]:
        listParts[-1] = list(filter(None, listParts[-1]))

    return listParts

if __name__ == '__main__':
    main()