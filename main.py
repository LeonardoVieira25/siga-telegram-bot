import hashlib
import requests
from bs4 import BeautifulSoup
import re
import json
import os
import glob
import telebot
import math

def verify_login(page):
    return "Você não está logado no Siga" not in page.text

def gerar_hash_md5(senha):
    senha_bytes = senha.encode('utf-8')
    hash_md5 = hashlib.md5()
    hash_md5.update(senha_bytes)
    senha_hash = hash_md5.hexdigest()    
    return senha_hash


def save_phpSessId_to_file(phpSessId, user):
    oldData = {}
    try:
        with open(f'./usuarios/{user}_userData.txt', "r", encoding="iso 8859-1") as file:
            print("file found")
            print(file)
            oldData = json.load(file)
    except FileNotFoundError:
        return

    oldData['phpsessid'] = phpSessId

    with open(f'./usuarios/{user}_userData.txt', "w", encoding="iso 8859-1") as file:
        file.write(json.dumps(oldData, ensure_ascii=False))

def get_phpSessId_from_file(user):
    try:
        file = open(f"./usuarios/{user}_userData.txt", "r", encoding="iso 8859-1")
        phpSessId = json.load(file)['phpsessid']
        file.close()
        return phpSessId
    except:
        return None

def authenticate(user, passwordHash):
    headers = {
        'Host': 'sigam1.ufjf.br',
        'Content-Length': '250',
        'Cache-Control': 'max-age=0',
        'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'https://sigam1.ufjf.br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Referer': 'https://sigam1.ufjf.br/index.php/siga/main',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Priority': 'u=0, i',
        'Connection': 'close'
    }

    data = {
        'user': user,
        'password': '',
        'uid': user,
        'pwd': '',
        'tries': '',
        'redir': '',
        'url': '',
        'challenge': '',
        'response': '',
        '__ISAJAXCALL': 'yes'
    }

    mainRequest = requests.post("https://sigam1.ufjf.br/index.php/siga/main", headers=headers, data=data)

    soup = BeautifulSoup(mainRequest.text, 'html.parser')



    phpSeed = mainRequest.headers['Set-Cookie'].split('PHPSESSID=')[1].split(';')[0]
    challenge_element = soup.find('input', {'id': 'challenge'})
    challenge_value = challenge_element.get('value')
    data['challenge'] = challenge_value
    # print(gerar_hash_md5(password))
    # data['response'] = gerar_hash_md5(user+":"+gerar_hash_md5(password)+":"+challenge_value)
    data['response'] = gerar_hash_md5(user+":"+passwordHash+":"+challenge_value)
    headers['Cookie'] = 'PHPSESSID=' + phpSeed

    requests.post("https://sigam1.ufjf.br/index.php/siga/login/authenticate/?", headers=headers, data=data)
    return phpSeed

def replace_key(match):
    key = match.group(2)
    if key.startswith('"') and key.endswith('"'):
        return match.group(1) + key + ':'
    else:
        return match.group(1) + '"' + key + '":'

def get_data(phpSessId):
    avaliacoes = []
    headers = {
        'Host': 'sigam1.ufjf.br',
        'Content-Length': '250',
        'Cache-Control': 'max-age=0',
        'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'https://sigam1.ufjf.br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Referer': 'https://sigam1.ufjf.br/index.php/siga/main',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Priority': 'u=0, i',
        'Connection': 'close',
        'Cookie': 'PHPSESSID=' + phpSessId
    }
    data_page = requests.get('https://sigam1.ufjf.br/index.php/siga/academico/acessoaluno/formNota', headers=headers)


    if not verify_login(data_page):
        print("sessão inválida")
        return False


    padrao = r'gridNotas\d+\.setData\(\s*(\[[^;]+)\);'
    resultados = re.findall(padrao, data_page.text, re.DOTALL)

    for resultado in resultados:
        resultado = resultado.replace('\n', '')

        resultado = re.sub(r'(\d+),(\d+)', r'\1.\2', resultado)

        resultado = re.sub(r'(\{|\,)(\w+):', r'\1"\2":', resultado)

        try:
            data = json.loads(resultado)
            avaliacoes.append(data)
        except json.JSONDecodeError as e:
            print(f"Não foi possível decodificar o JSON: {e}")

    disciplinas = []
    # Expressão regular para extrair os objetos dentro de setData()
    padrao = r'gridMatriculas.setData\((.*?)\);'

    # Procurando o padrão na string e obtendo os dados dentro dos parênteses
    resultado = re.search(padrao, data_page.text, re.DOTALL)

    if resultado:
        # Capturando o conteúdo dentro dos parênteses
        objetos = resultado.group(1)
        
        objetos = re.sub(r'(\{|\,)(\w+):', r'\1"\2":', objetos)
        # Exibindo os objetos encontrados
        try:
            data = json.loads(objetos)
            disciplinas = data
        except json.JSONDecodeError as e:
            print(f"Não foi possível decodificar o JSON: {e}")

    else:
        print("Nenhum dado encontrado.")

    for i in range(len(disciplinas)):
        disciplina = disciplinas[i]
        disciplina['avaliacoes'] = avaliacoes[i]
    

    return disciplinas

def save_result_to_file(result, user):
    with open(f'./results/{user}_result.txt', "w", encoding="iso 8859-1") as file:
        file.write(json.dumps(result, ensure_ascii=False))
    

def read_result_from_file(user):
    try:
        file = open(f'./results/{user}_result.txt', "r", encoding="iso 8859-1")
        result = file.read()
        file.close()
        return json.loads(result)
    except:
        return None



def get_user_data_files():
    folder_path = './usuarios'
    file_pattern = '*userData.txt'
    file_path_pattern = os.path.join(folder_path, file_pattern)
    user_data_files = glob.glob(file_path_pattern)
    return user_data_files

def compareLists(list1, list2):
    if len(list1) != len(list2):
        return False
    for i in range(len(list1)):
        if list1[i] != list2[i]:
            return False
    return True

def encontrar_diferenca(lista1, lista2):
    if lista1 == None:
        lista1 = []
    set1 = {disciplina['nomeDisciplina']: disciplina for disciplina in lista1}
    set2 = {disciplina['nomeDisciplina']: disciplina for disciplina in lista2}

    diferenca = {}
    for disciplina, info in set2.items():
        if disciplina in set1:
            avaliacoes_1 = set1[disciplina]['avaliacoes']
            avaliacoes_2 = info['avaliacoes']
            diff_avaliacoes = [x for x in avaliacoes_2 if x not in avaliacoes_1]
            if diff_avaliacoes:
                diferenca[disciplina] = diff_avaliacoes
        else:
            diferenca[disciplina] = info['avaliacoes']

    return diferenca

def get_user_chat_id(user):
    try:
        file = open(f'./usuarios/{user}_userData.txt', "r", encoding="iso 8859-1")
        chat_id = json.load(file)['chat_id']
        file.close()
        return chat_id
    except:
        return None
    

def generate_pretty_message(diferenca):
    message = ""
    print(diferenca)
    for nomeDisciplina, avaliacoes in diferenca.items():
        print("nomeDisciplina")
        print(nomeDisciplina)
        
        message += f"{nomeDisciplina}\n"
        for avaliacao in avaliacoes:
            percentage = (float(avaliacao['nota'])/float(avaliacao['peso']))*100
            nVerdes = math.floor(percentage/10)
            nVermelhos = 10 - nVerdes
            message += f"{avaliacao['descricao']}:\n{'🟩'*nVerdes}{'🟥'*nVermelhos} {round(percentage, 1)} %\n"
        message += "\n\n"
    return message

def main():
    files = get_user_data_files()
    for file in files:
        with open(file, "r") as file:
            user_data = json.load(file)
            phpSessId = get_phpSessId_from_file(user_data['matricula'])
            if phpSessId == None:
                print("\033[91mSessão não encontrada!\033[0m")
                phpSessId = authenticate(user_data['matricula'], user_data['senhaHash'])
                save_phpSessId_to_file(phpSessId, user_data['matricula'])
            

            result = get_data(phpSessId)
            if result == False:
                print("\033[91mSessão expirada!\033[0m")
                phpSessId = authenticate(user_data['matricula'], user_data['senhaHash'])
                save_phpSessId_to_file(phpSessId, user_data['matricula'])
                result = get_data(phpSessId)


            if str(result) == str(read_result_from_file(user_data['matricula'])):
                print("result is equal to read_result_from_file()")
            else:
                changes = encontrar_diferenca(read_result_from_file(user_data['matricula']), result)


                bot = telebot.TeleBot(os.getenv("TELEBOT_TOKEN"))
                chat_id = get_user_chat_id(user_data['matricula'])
                bot.send_message(chat_id, f"Tem nota nova pra você!")
                bot.send_message(chat_id, f"{generate_pretty_message(changes)}")

                save_result_to_file(result, user_data['matricula'])
                print("result is not equal to read_result_from_file()")





if __name__ == '__main__':
    main()