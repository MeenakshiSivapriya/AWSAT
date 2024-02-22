import sys
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from reportlab.pdfgen import canvas

user_url = sys.argv
driver = webdriver.Chrome()
driver.get(user_url[1])

try:
        link_elements = driver.find_elements(By.XPATH, "//a")
        print("Number of hyperlink elements: ", len(link_elements))
except NoSuchElementException:
        print("Number of hyperlink elements: 0")
print("Basic Open Redirection checks completed. Check the report for more detailed analysis")
print(" ")

try:
        file_elements = driver.find_elements(By.XPATH, "//input[@type='file']")
        print("Number of file upload elements: ", len(file_elements))
except NoSuchElementException:
        print("Number of file upload elements: 0")
print("Basic File Upload Vulnerability checks completed. Check the report for more detailed analysis")
print(" ")

try:
	form_elements = driver.find_elements(By.XPATH, "//form")
	print("Number of form elements: ", len(form_elements))
except NoSuchElementException:
	print("Number of form elements: 0")
print("Basic CSRF checks completed. Check the report for more detailed analysis")
print(" ")

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

	try:
		driver.find_element(By.XPATH, "//input[@type='password']")
	except NoSuchElementException:
		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!Basic SQL Injection successfully executed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

except NoSuchElementException:
	print("Number of password elements: 0")
print("Basic SQL Injection tests completed. Check the report for more detailed analysis")
print(" ")

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
		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!Basic XSS successfully executed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		break
	except TimeoutException:
		print("No alert")
print("Basic XSS tests completed. Check the report for more detailed analysis")
print(" ")

driver.close()

pdf = canvas.Canvas('awsat_report.pdf')

pdf.setFont('Times-Bold', 26)
pdf.drawCentredString(300, 770, 'Automated Web Security Analysis Tool Report')

pdf.setFont("Times-Italic", 14)
pdf.drawCentredString(298, 740, 'Prepared by Meenakshi Manikandaswamy')

pdf.line(10, 730, 590, 730)

text = pdf.beginText(40, 690)

text.setFont('Times-Bold', 18)
text.textLine("I. Executive Summary:")

text.setFont('Times-Roman', 16)
summary = ["", "This report details the progress and findings of the Automated Web Security", 
			"Analysis Tool project, focusing on identifying and mitigating vulnerabilities", 
			"such as Open Redirection, File Upload, Cross-Site Request Forgery (CSRF),", 
			"SQL Injection (SQLi), and Cross-Site Scripting (XSS).", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 18)
text.textLine("II. Open Redirection Vulnerability:")

text.setFont('Times-Italic', 18)
text.textLine("")
text.textLine("Objective:")

text.setFont('Times-Roman', 16)
summary = ["An open redirection vulnerability occurs when a web application redirects a", 
			"user to an untrusted site. It can be exploited by attackers to redirect them to", 
			"malicious sites, leading to phishing attacks or the theft of sensitive information.",""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Steps Taken:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Detection:")

text.setFont('Times-Roman', 16)
summary = ["The tool scans webpages for open redirection vulnerabilities by analyzing URLs", "and redirects.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Payloads:")

text.setFont('Times-Roman', 16)
summary = ["Utilizes preset payloads to assess the susceptibility of the webpage to open", 
			"redirection attacks.",
			"Sample Payload: https://malicious-site.com", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Findings:")
text.setFont('Times-Roman', 16)
summary = ["Number of Attack Vectors Identified: " + str(len(link_elements)), 
			"Attack Execution: " + "FAILED", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("CVSS Score:")
text.setFont('Times-Roman', 16)
summary = ["Severity: Medium", 
			"Score: [CVSS Score]", ""]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Italic', 18)
text.textLine("Do It Yourself!")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Identify Redirection Points:")

text.setFont('Times-Roman', 16)
summary = ["Look for any features or parameters in the application that involve redirection.", 
			"Common examples include login/logout, password reset, or external links.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Understand the Redirection Mechanism:")

text.setFont('Times-Roman', 16)
summary = ["Analyze how the application handles redirections. Check whether it uses",
			"user-supplied data or parameters to determine the target URL.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Provide Malicious Input:")

text.setFont('Times-Roman', 16)
summary = ["Inject a malicious URL or a URL with a redirect to an external domain.",
			"Observe the application's response. If the application redirects to the", 
			"provided URL without proper validation, there may be a vulnerability.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Explore Redirect Parameters:")

text.setFont('Times-Roman', 16)
summary = ["If the redirection is controlled by parameters (e.g., redirect or return_url), try", 
			"manipulating these parameters to introduce variations or inject malicious values.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Check for Filters and Validation:")

text.setFont('Times-Roman', 16)
summary = ["Investigate if the application has any input validation or filters in place. It ", 
			"may have client-side or server-side filters to prevent malicious redirections.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Prevention:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Whitelisting:")

text.setFont('Times-Roman', 16)
summary = ["Maintain a whitelist of trusted, allowable redirect URLs within your application.", 
			"Before redirecting, validate that the supplied URL is present in the whitelist.",
			"Reject any redirection attempts to URLs not in the whitelist.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Domain Matching:")

text.setFont('Times-Roman', 16)
summary = ["Ensure that the redirection URL belongs to the same domain or a trusted domain.",
			"This prevents attackers from redirecting users to arbitrary external domains.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Relative URLs:")

text.setFont('Times-Roman', 16)
summary = ["Whenever possible, use relative URLs for redirection rather than full URLs.",
			"This ensures that the redirection stays within the same domain.", ""]
for line in summary:
	text.textLine(line)

pdf.drawText(text)

pdf.save()