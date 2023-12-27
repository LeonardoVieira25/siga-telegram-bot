from telegram import Update
import telebot
import os
import json
import hashlib

bot = telebot.TeleBot(os.getenv("TELEBOT_TOKEN"))
def gerar_hash_md5(senha):
    senha_bytes = senha.encode('utf-8')
    hash_md5 = hashlib.md5()
    hash_md5.update(senha_bytes)
    senha_hash = hash_md5.hexdigest()    
    return senha_hash

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Bem vindo ao siga do leleo, digite /help para ver os comandos disponíveis")

@bot.message_handler(commands=['help'])
def send_welcome(message):
    bot.reply_to(message, '''
    Pra usar você tem que registrar
    /register <matricula> <senha>
    /hashRegister <matricula> <senhaHash>
                 
    Eu não guardo sua senha, só o hash dela, mas se você não confia em mim, use o hashRegister passando um hash md5 da sua senha (https://www.md5hashgenerator.com/)
''')

@bot.message_handler(commands=['register'])
def register(message):
    matricula = message.text.split()[1]
    senha = message.text.split()[2]
    data = {
        "chat_id": message.chat.id,
        "matricula": matricula,
        "senhaHash": gerar_hash_md5(senha),
        "phpsessid": None,
    }
    with open(f"usuarios/{matricula}_userData.txt", "w") as file:
        json.dump(data, file)

    bot.reply_to(message, "Registrado com sucesso 👍")

@bot.message_handler(commands=['hashRegister'])
def register(message):
    matricula = message.text.split()[1]
    senha = message.text.split()[2]
    data = {
        "chat_id": message.chat.id,
        "matricula": matricula,
        "senhaHash": senha,
        "phpsessid": None,
    }
    with open(f"usuarios/{matricula}_userData.txt", "w") as file:
        json.dump(data, file)

    bot.reply_to(message, "Registrado com sucesso 👍")


# response to a unknown command or message
@bot.message_handler(func=lambda message: True)
def echo_all(message):
    bot.reply_to(message, "Comando não reconhecido.")



bot.infinity_polling()