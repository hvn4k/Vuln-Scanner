__author__ = "Muhammad Anas Khan"
from pprint import pprint
from urllib.parse import parse_qsl, urlencode, urlsplit, urlparse
import sys ,requests,time,sys,logs,html
import  os,datetime,time
from sys import argv, exit, version_info
import colorama
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
import argparse
from colorama import Fore, Back, Style
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from colorama import Fore, Style

Gr='\033[1;32m'
Ye='\033[1;33m'
Wh='\033[1;37m'
colorama.init()


#timestamp= datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
#cwd = os.path.dirname(os.path.abspath( __file__ ))
#sys.path.insert(0,cwd+'/..')
security_set = False

#work_dir = cwd +'/logs/'



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
    
def clear():
    if 'linux' in sys.platform:
        os.system('clear')
    elif 'darwin' in sys.platform:
        os.system('clear')
    else:
        os.system('cls')   

def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
   
    details = {}
    
    action = form.attrs.get("action", "").lower()
  
    method = form.attrs.get("method", "get").lower()
    
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
   
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    
    
    target_url = urljoin(url, form_details["action"])
   
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
           
            data[input_name] = input_value

    
    print(f"[+] Data: {data}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        
        return requests.get(target_url, params=data)

def scan_xss(url ):
  
   
    forms = get_all_forms(url)
  
    
    
    is_vulnerable = False
    
    with open('payload.txt', 'r') as file:
        payloads = file.readlines()

    for form in forms:
        form_details = get_form_details(form)
        

        for payload in payloads:
            content = submit_form(form_details, url, payload.strip()).content.decode()
            #print(content)
            for line in content.splitlines():
                
                if 'alert' in line and 'script' in line and '/script' in line or 'alert' in line and 'Script' in line or '/Script' in line:
                    #print(line)
                    print(f"{Fore.RED}[+] XSS Detected on {url}{Style.RESET_ALL}")
                    #print("line: ",line)
                    print(f"{Fore.RED}[*] Form details:{Style.RESET_ALL}")
                    pprint(form_details)
                    is_vulnerable = True
		        
                    break  
                elif 'alert' in line and '/script' in line and payload in line:
                    print(f"{Fore.RED}[+] XSS Detected on {url}{Style.RESET_ALL}")
                    
                    print(f"{Fore.RED}[*] Form details:{Style.RESET_ALL}")
                    pprint(form_details)
                    is_vulnerable = True
		        
                    break  

            if is_vulnerable == True:
                print(Fore.RED + "Vulnerability detected. Stopping further testing.")
                break    

    return is_vulnerable
    
def print_result(payload, result_type, content=None):
    result_message = f"Payload: {payload} - {result_type}"
    if content:
        result_message += f"\nContent: {content}"

    if result_type == "SQL Injection - Vulnerable":
        print(Fore.RED + result_message)  
    else:
        print(Fore.GREEN + result_message)  

def test_sql_injection_payload(BASE_URL,driver, payload):
    
    security_set = False
    security_set  
    vulnerability_detected = False  

    try:
        driver.get(BASE_URL)

        if not security_set:
            driver.get('http://127.0.0.1:42001/security.php')
            driver.find_element(By.NAME, "security").click()
            driver.find_element(By.CSS_SELECTOR, "option[value='low']").click()
            driver.find_element(By.NAME, "seclev_submit").click()

            driver.get(BASE_URL)

            security_set = True

        input_field = driver.find_element("name", "id")
        submit_button = driver.find_element("name", "Submit")

        input_field.send_keys(payload)
        submit_button.click()

        try:
            WebDriverWait(driver, 5)

            if '<pre>' in driver.page_source:
                pre_tag = driver.find_element(By.TAG_NAME, 'pre')
                content = pre_tag.text
                print_result(payload, "SQL Injection - Vulnerable")
                vulnerability_detected = True 

            else:
                print_result(payload, "Not Vulnerable")

        except TimeoutException:
            driver.get(BASE_URL)
            print_result(payload, "Timeout waiting for changes in the page content")

        except NoSuchElementException as e:
            driver.get(BASE_URL)
            print_result(payload, f"Element not found: {e}")

    except Exception as e:
        driver.get(BASE_URL)
        print_result(payload, f"Exception occurred: {e}")

    finally:
        return vulnerability_detected  
if __name__ == "__main__":
        banner()
        data = input(Fore.GREEN +"* [ X ] For XSS Scanning \n* [ S ] For SQL Injection\n")
        user_input = data.upper()
        if(user_input == "X"):
                # clear()
                url = input("Please Enter Site Link With : ")
                scan_xss(url)
        
        elif(user_input == "S"):
                url = input("Please Enter Site Link  : ")
                BASE_URL=url
                try:
                    with open('inject.txt', 'r') as f:
                        sql_payloads = [line.strip() for line in f]
                        
                    options = webdriver.FirefoxOptions()
                    options.add_argument('--headless')  

                    driver = webdriver.Firefox(options=options)
                    
                    driver.get(BASE_URL)

                    
                    for payload in sql_payloads:
                        if test_sql_injection_payload(BASE_URL,driver, payload):
                            print(Fore.RED + "Vulnerability detected. Stopping further testing.")
                            break  

                    print(Fore.GREEN + "Testing completed. Results written to the log file.")

                except Exception as e:
                    print(f"Error: {e}")

                finally:
                    if 'driver' in locals():
                        driver.quit()

                 
