import sys
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By

user_url = sys.argv
driver = webdriver.Chrome()
driver.get(user_url[1])
driver.close()
