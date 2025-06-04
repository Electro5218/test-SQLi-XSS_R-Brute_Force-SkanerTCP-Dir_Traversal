<h1 align="center">DVWA Vulnerability Scanner</h1>

<p align="center">
  Skrypt do automatycznego testowania podatności na popularne ataki webowe w DVWA (Damn Vulnerable Web Application).
</p>

<hr>

<h2>Opis projektu</h2>

<p>Ten skrypt w Pythonie wykorzystuje <code>requests</code> i <code>BeautifulSoup</code> do testowania podatności w aplikacji DVWA na lokalnym serwerze.</p>
<ul>
  <li>SQL Injection</li>
  <li>Cross-Site Scripting (XSS)</li>
  <li>Brute-force (na logowaniu)</li>
  <li>Directory Traversal</li>
  <li>Skanowanie portów TCP</li>
</ul>

<hr>

<h2>Wymagania</h2>

<ul>
  <li>Python 3.6+</li>
  <li>Biblioteki Python:
    <ul>
      <li><code>requests</code></li>
      <li><code>beautifulsoup4</code></li>
    </ul>
  </li>
</ul>

<p>Możesz je zainstalować za pomocą pip:</p>

<pre><code>pip install requests beautifulsoup4
</code></pre>

<hr>

<h2>Przygotowanie DVWA</h2>

<ol>
  <li>Zainstaluj i uruchom DVWA lokalnie, np. na serwerze Apache + PHP + MySQL.</li>
  <li>Upewnij się, że DVWA jest dostępne pod adresem: <br>
  <code>http://localhost/DVWA/</code></li>
  <li>Ustaw poziom bezpieczeństwa DVWA na <strong>low</strong> (w panelu DVWA -> Security) dla pełnego działania testów.</li>
  <li>Ustaw standardowe dane logowania w DVWA:<br>
    <ul>
      <li>Username: <code>admin</code></li>
      <li>Password: <code>password</code></li>
    </ul>
  </li>
</ol>

<hr>

<h2>Uruchomienie skryptu</h2>

<ol>
  <li>Pobierz plik <code>testpodatnosciDVWA.py</code> na swój komputer.</li>
  <li>Otwórz terminal lub konsolę w katalogu, gdzie znajduje się skrypt.</li>
  <li>Uruchom skrypt poleceniem:<br>
  <pre><code>python3 testpodatnosciDVWA.py
  </code></pre></li>
  <li>Po zalogowaniu pojawi się menu z opcjami do testów. Wybierz test, wpisując odpowiedni numer.</li>
</ol>

<hr>

<h2>Specyfikacja działania</h2>

<ul>
  <li>Skrypt automatycznie pobiera token CSRF z DVWA, aby prawidłowo wykonywać żądania POST.</li>
  <li>Dla każdego testu wysyła różne payloady i analizuje odpowiedź strony, wypisując wyniki w konsoli.</li>
  <li>Skaner portów pozwala sprawdzić otwarte porty TCP na wskazanym hoście.</li>
</ul>

<hr>

<h2>Uwagi</h2>

<ul>
  <li>Skrypt testuje podatności na środowisku lokalnym — nie używaj go na serwerach bez zgody właściciela!</li>
  <li>DVWA musi działać na <code>localhost</code> i być dostępne pod podanymi URL.</li>
  <li>W razie problemów z połączeniem sprawdź konfigurację serwera Apache oraz zapory systemowej.</li>
</ul>
