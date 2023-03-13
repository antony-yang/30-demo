import requests

class GuanHTTP(object):

    def __init__(self):
        self.headers = {
            "User-Agent": "dongjian",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br"
        }

    def get(self, url):
        try:
            res = requests.get(url, headers=self.headers)
            return {"res": 1, "value": res}
        except Exception as e:
            return {"res": 0, "value": str(e)}

    def post(self, url, files=None, json=None):
        try:
            if files == None:
                res = requests.post(url, headers=self.headers, json=json, timeout=2)
            else:
                res = requests.post(url, headers=self.headers, files=files, timeout=2)
            return {"res": 1, "value": res}
        except Exception as e:
            return {"res": 0, "value": str(e)}

    def head(self):
        pass

    def put(self):
        pass

    def delete(self):
        pass

    def options(self):
        pass

    # support large file download
    def getFile(self, url, path):
        try:
            res = requests.get(url, headers=self.headers, stream=True)
            with open(path, "wb") as f:
                for chunk in res.iter_content(chunk_size=1024*1024):
                    if chunk:
                        f.write(chunk)
            return {"res": 1, "value": "download success"}
        except Exception as e:
            return {"res": 0, "value": str(e)}
