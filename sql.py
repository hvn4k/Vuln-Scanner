import os
import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from colorama import Fore  # Import Fore from colorama

BASE_URL = 'http://127.0.0.1:42001/vulnerabilities/sqli/'

security_set = False

def print_result(payload, result_type, content=None):
    result_message = f"Payload: {payload} - {result_type}"
    if content:
        result_message += f"\nContent: {content}"

    if result_type == "SQL Injection - Vulnerable":
        print(Fore.RED + result_message)  # Use Fore.GREEN for SQL Injection detection
    else:
        print(Fore.GREEN + result_message)  # Use Fore.RED for Not Vulnerable

def test_sql_injection_payload(driver, payload):
    global security_set  # Use the global variable
    vulnerability_detected = False  # Flag to track vulnerability detection

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
                vulnerability_detected = True  # Set the flag

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
        return vulnerability_detected  # Return the flag

def main():
    try:
        with open('inject.txt', 'r') as f:
            sql_payloads = [line.strip() for line in f]

        driver = webdriver.Firefox()
        driver.get(BASE_URL)

        print(Fore.GREEN + "Testing for SQL Injection:")
        for payload in sql_payloads:
            if test_sql_injection_payload(driver, payload):
                print(Fore.RED + "Vulnerability detected. Stopping further testing.")
                break  # Stop testing if vulnerability detected

        print(Fore.GREEN + "Testing completed. Results written to the log file.")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        if 'driver' in locals():
            driver.quit()

if __name__ == "__main__":
    main()

