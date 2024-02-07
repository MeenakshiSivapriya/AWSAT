import sys
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

user_url = sys.argv
driver = webdriver.Chrome()
driver.get(user_url[1])
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
		print("Basic XSS tests passed. Check the report for more detailed analysis")
driver.close()
