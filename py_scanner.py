__author__ = "Muhammad Anas Khan"

from urllib.parse import parse_qsl, urlencode, urlsplit, urlparse
import sys ,requests,time,sys,logs,html
import  os,datetime
from sys import argv, exit, version_info
import colorama

from colorama import Fore, Back, Style
colorama.init()


timestamp= datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
cwd = os.path.dirname(os.path.abspath( __file__ ))
sys.path.insert(0,cwd+'/..')


work_dir = cwd +'/logs/'



headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0'}

errorMessage = [
    "SQL syntax",
    "SQL",
    "Sql",
    "sql",
    "MySql",
    "MySQL",
    "mysql",
    "Syntax",
    "SYNTAX",
    "You have an error",
]
def banner():
        print(Fore.GREEN +'''            
            SSD LAB vulnerability scanner 
            By
            Muhammad Anas Khan
            Ahsan Raza
            Hamdan Noori
         ''')  
      
        print()
        print()
    
    
def inject(url):
    base = url.split("?")[0] + "?"
    parameters = url.split("?")[1]
    count = 0
    if "&" in parameters: 
        parameters = parameters.split("&")
        for parameter in parameters:
            if count == 0:
                url = base + parameter + "'"
                count = count + 1
            else:
                url = url + "&" + parameter + "'"
    else:
        url = base + parameters + "'"
    return url

def check(url): 
    c = 0
    for error in errorMessage:
        try:
          r = requests.get(url, headers=headers)
        except requests.exceptions.ConnectionError:
          break
        except requests.exceptions.TooManyRedirects:
            break

        if error in r.text:
            c = 1
            print(url + Fore.GREEN +" [Vulnerable]")
            break
    
    if c == 0:
        print(url + Fore.GREEN +" [Not Vulnerable]")
    

# def scan_html(payload,url, logs_des):
def clear():
    if 'linux' in sys.platform:
        os.system('clear')
    elif 'darwin' in sys.platform:
        os.system('clear')
    else:
        os.system('cls')   

def scan_xss():
        print(Fore.GREEN+ "Welcome to " + Fore.RED + "XSS Scanner" + Style.RESET_ALL)
        print()
        print(Fore.GREEN + "Are you Ready For Scanning")
        time.sleep(2)
        print()
        try:
                site = input(Fore.GREEN + "Enter your target for scanning (with parameters): ")
                r = requests.post(site)
                time.sleep(2)
                print(Fore.GREEN + "Site Responded Well")
        except:
                print()
                time.sleep(1)
                print(Fore.GREEN + "Site is not reachable")
                sys.exit(0)
        payload = "payload.txt"
        print(Fore.GREEN + "Testing...!\n")
        time.sleep(0)
        f = open(payload, 'r')
        for line in f:
                print(Fore.GREEN + "Testing the payload" + str(1))
                if line in requests.get(site + line).text:
                        print(Fore.GREEN + "XSS FOUND HERE!!!")
                        print(Fore.GREEN +"URL + Payload : "+ Fore.YELLOW +requests.get(site + line).url)
                        print(Fore.GREEN +"URL : "+Fore.YELLOW +site)
                        print(Fore.GREEN +"Payload : "+Fore.YELLOW +line)
                        sys.exit(0)  
                else:
                        print(Fore.GREEN + "The Payload " + str(1) + " did not trigger XSS here" )
       
        
def html(url):
        import html
        domain = urlparse(url).netloc
        logs_des = work_dir+str(domain)+timestamp+'.txt'

        logs.create_log(logs_des,"Scanning Started for : "+str(domain))
        payload="<h1>Hello</h1>"
        logs.create_log(logs_des,"Payload Used : "+str(payload))

        param = dict(parse_qsl(urlsplit(url).query))
        tainted_params = {x: payload for x in param}
        logs.create_log(logs_des,"Params : "+str(tainted_params))
        if len(tainted_params) > 0:
                attack_url = urlsplit(url).geturl() + urlencode(tainted_params)
                resp = requests.get(url=attack_url, data = payload, headers=headers)
                if resp.status_code == 200:  
                        if payload in resp.text:
                                attack_encode=html.escape(attack_url)
                                print(Fore.GREEN +"\nScanning Started....! \n")
                                logs.create_log(logs_des,"HTML Injection Found : "+str(attack_url))
                                print(Fore.GREEN +"HTML Injection Found at : "+ Fore.YELLOW+attack_url)
                                print(Fore.GREEN +"URL : "+ Fore.YELLOW+url)
                                print(Fore.GREEN +"Payload : "+ Fore.YELLOW+payload)
                        else:
                                logs.create_log(logs_des,"No HTML Injection Found  : "+str(url))
                                return print("This URL is not Vulnerable" )
                else:
                        return  print("Site Can Not Be Accessed" ) 
if __name__ == "__main__":
        banner()
        # data = input(Fore.YELLOW + "For XSS Please Enter X \n  For HTML Injection Please Enter H/ For SQLi Please Enter S : ")
        data = input(Fore.GREEN +"* [ X ] For XSS Scanning \n* [ H ] For HTML Injection \n* [ S ] For SQL Injection\n")
        user_input = data.upper()
        if(user_input == "X"):
                # clear()
                scan_xss()
        elif (user_input == "H"):
                # clear()
                url = input('Plase enter valid URL : ') 
                html(url)
        elif(user_input == "S"):
                url = input("Please Enter Site Link With Parameters : ")
                injected = inject(url)
                check(injected) 
