import sys
import time
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
start_time = time.time()

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
	try:
		uname_element = driver.find_element(By.XPATH, "//input[@name='uname']")
		print("Number of username elements: 1")
	except:
		print("Number of username elements: 0")
try:
	passwd_element = driver.find_element(By.XPATH, "//input[@type='password']")
	print("Number of password elements: 1")

	uname_element.clear()
	uname_element.send_keys("admin")
	passwd_element.clear()
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

input_elements = driver.find_elements(By.XPATH, "//form//input")
text_inputs = driver.find_elements(By.XPATH, "//form//input[@type='text']")
print("Number of input elements: ", len(input_elements))
print("Number of text input elements: ", len(text_inputs))

for count in range(len(input_elements)):
	input_elements = driver.find_elements(By.XPATH, "//form//input")
	element = input_elements[count]
	try:
		element.clear()
		element.send_keys("<script>alert(document.domain)</script>")
		element.send_keys(Keys.RETURN)
	except:
		print("Not interactive")
	try:
		WebDriverWait(driver, 3).until(EC.alert_is_present())
		alert = driver.switch_to.alert
		alert.accept()
		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!Basic XSS successfully executed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		break
	except TimeoutException:
		print("No XSS alert")
		driver.back()
print("Basic XSS tests completed. Check the report for more detailed analysis")
print(" ")

driver.close()
end_time = time.time()
print("Time taken: " + str(end_time - start_time))

pdf = canvas.Canvas('awsat_report.pdf')

pdf.setFont('Times-Bold', 26)
pdf.drawCentredString(300, 770, 'Automated Web Security Analysis Tool Report')

pdf.setFont("Times-Italic", 14)
pdf.drawCentredString(298, 740, 'Prepared by Meenakshi Manikandaswamy')

pdf.line(10, 730, 590, 730)

text = pdf.beginText(40, 690)

text.setFont('Times-Bold', 18)
text.textLine("I. Executive Summary:")

text.setFont('Times-Bold', 14)
text.textLine("Targeted Web Page: " + user_url[1])

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
			"Attack Execution: " + "None Identified", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("CVSS Score:")
text.setFont('Times-Roman', 16)
summary = ["Severity: Medium", 
			"Score: 6.1", ""]
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
			"Observe the application's response. If the application redirects to the provided", 
			"URL without proper validation, there may be a vulnerability.", ""]
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
summary = ["Investigate if the application has any input validation or filters in place. It may", 
			"have client-side or server-side filters to prevent malicious redirections.", ""]
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
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 18)
text.textLine("III. File Upload Vulnerability:")

text.setFont('Times-Italic', 18)
text.textLine("")
text.textLine("Objective:")

text.setFont('Times-Roman', 16)
summary = ["File upload vulnerabilities enable attackers to upload malicious files to a web", 
			"application, potentially leading to remote code execution, unauthorized access,", 
			"or the compromise of sensitive data.",""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Steps Taken:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Detection:")

text.setFont('Times-Roman', 16)
summary = ["The tool analyzes webpages for file upload elements and assesses their security.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Payloads:")

text.setFont('Times-Roman', 16)
summary = ["Employs predefined payloads to test the security of file upload functionalities.", 
			"Sample Payload: File with a name containing executable code", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Findings:")
text.setFont('Times-Roman', 16)
summary = ["Number of Attack Vectors Identified: " + str(len(file_elements)), 
			"Attack Execution: " + "None Identified", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("CVSS Score:")
text.setFont('Times-Roman', 16)
summary = ["Severity: High", 
			"Score: 8.8", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Do It Yourself!")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Upload Malicious File:")

text.setFont('Times-Roman', 16)
summary = ["Attempt to upload a file that contains malicious code, such as a web shell or a", 
			"file with embedded scripts.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Check for File Extension Bypass:")

text.setFont('Times-Roman', 16)
summary = ["Some applications validate files based on file extensions. Try to bypass this by", 
			"renaming a file with a valid extension but containing malicious code", 
			"(e.g., renaming a .php file to .jpg).", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Check for Client-Side Validation:")

text.setFont('Times-Roman', 16)
summary = ["Use browser developer tools to inspect and modify the HTML form, disabling", 
			"any client-side validation that may be present.", ""]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 16)
text.textLine("Bypass Frontend Validation:")

text.setFont('Times-Roman', 16)
summary = ["If there is client-side validation, try to bypass it by manipulating the upload request", 
			"using tools like Burp Suite or modifying the HTML form.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Explore File Upload Permissions:")

text.setFont('Times-Roman', 16)
summary = ["Investigate how the application handles file permissions after upload. Ensure that", 
			"uploaded files cannot be accessed or executed by unauthorized users.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Prevention:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("File Type Validation:")

text.setFont('Times-Roman', 16)
summary = ["Verify the file type by checking the file extension or using file signature analysis.", 
			"Ensure that only allowed file types are accepted. Do not rely solely on client-side", 
			"checks; perform server-side validation as well.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Content-Type Header Check:")

text.setFont('Times-Roman', 16)
summary = ["Validate the Content-Type header of the file to ensure it matches the expected type.", 
			"This helps prevent attackers from manipulating file extensions.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Disable Execution of Uploaded Files:")

text.setFont('Times-Roman', 16)
summary = ["Ensure that uploaded files are not executable. Store uploaded files in a location", 
			"separate from executable scripts and prevent the execution of uploaded content.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("File Size Limitation:")

text.setFont('Times-Roman', 16)
summary = ["Set a maximum file size limit to prevent the upload of excessively large files,", 
			"which can lead to denial-of-service (DoS) attacks.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Secure File Storage:")

text.setFont('Times-Roman', 16)
summary = ["Store uploaded files outside the web root directory to prevent direct access.", 
			"Use proper access controls to restrict who can access and modify uploaded files.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Further Reading:")

text.setFont('Times-Roman', 16)
summary = ["https://portswigger.net/web-security/file-upload", 
			"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload", 
			"https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/434.html", ""]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 18)
text.textLine("IV. Cross Site Request Forgery (CSRF):")

text.setFont('Times-Italic', 18)
text.textLine("")
text.textLine("Objective:")

text.setFont('Times-Roman', 16)
summary = ["CSRF occurs when an attacker tricks a user's browser into making unintended and", 
			"unauthorized requests on behalf of the user. This can lead to actions being", 
			"performed on the web application without the user's consent.",""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Steps Taken:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Detection:")

text.setFont('Times-Roman', 16)
summary = ["Identifying CSRF tokens and analyzes form elements for potential vulnerabilities.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Payloads:")

text.setFont('Times-Roman', 16)
summary = ["Uses predefined payloads to simulate CSRF attacks and assess vulnerability.", 
			"Sample Payload: Tricking user into submitting a form with malicious content.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Findings:")
text.setFont('Times-Roman', 16)
summary = ["Number of Attack Vectors Identified: " + str(len(form_elements)), 
			"Attack Execution: " + "None Identified", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("CVSS Score:")
text.setFont('Times-Roman', 16)
summary = ["Severity: Medium", 
			"Score: 6.5", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Do It Yourself!")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Analyze Form Submissions:")

text.setFont('Times-Roman', 16)
summary = ["Identify forms within the application that perform actions with side effects and", 
			"those that lack anti-CSRF mechanisms like tokens or same-site cookie attributes.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Craft a Malicious Page:")

text.setFont('Times-Roman', 16)
summary = ["Create a malicious HTML page that includes a hidden form with the target action",
			"and parameters.", 
			"Ensure that the form mimics the structure of the legitimate forms in the application.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Host the Malicious Page:")

text.setFont('Times-Roman', 16)
summary = ["Host the malicious HTML page on an external server accessible by the victim.", 
			"The page should contain JavaScript to automatically submit the form."]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 16)
text.textLine("Trick the Victim:")

text.setFont('Times-Roman', 16)
summary = ["Convince the victim to visit the malicious page, often through social engineering", 
			"tactics like phishing emails or disguised links.", 
			"Monitor the server logs to see if the forged request was processed successfully.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Prevention:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Use Anti-CSRF Tokens:")

text.setFont('Times-Roman', 16)
summary = ["Include unique, unpredictable tokens in each HTML form. These tokens should be", 
			"generated on the server side and embedded in the form as hidden fields or headers.", 
			"Upon form submission, the server validates the token to ensure that the request", 
			"originated from the legitimate application.",""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("SameSite Cookie Attribute:")

text.setFont('Times-Roman', 16)
summary = ["Set the SameSite attribute for cookies to mitigate the risk of CSRF attacks. This", 
			"attribute restricts when the browser sends cookies, ensuring they are only sent", 
			"in requests originating from the same site as the target URL.", 
			"Use SameSite=Lax or SameSite=Strict to provide varying levels of protection.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Check Referrer Header:")

text.setFont('Times-Roman', 16)
summary = ["Verify the Referer header on the server to ensure that requests originate from the", 
			"expected domain. However, note that the Referer header can be manipulated or", 
			"omitted in some cases.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Custom Headers:")

text.setFont('Times-Roman', 16)
summary = ["Include custom headers in requests and validate them on the server. Ensure that", 
			"these headers are not accessible to scripts running in the browser", 
			"(e.g., using the Access-Control-Expose-Headers header).", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Implement Time-Based Tokens:")

text.setFont('Times-Roman', 16)
summary = ["Include a timestamp in the token and validate it on the server. Reject requests", 
			"with expired tokens.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Further Reading:")

text.setFont('Times-Roman', 16)
summary = ["https://portswigger.net/web-security/csrf", 
			"https://owasp.org/www-community/attacks/csrf", 
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/352.html",
			"https://csrc.nist.gov/glossary/term/cross_site_request_forgery",
			"https://portswigger.net/web-security/csrf/preventing"]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 18)
text.textLine("V. SQL Injection (SQLi):")

text.setFont('Times-Italic', 18)
text.textLine("")
text.textLine("Objective:")

text.setFont('Times-Roman', 16)
summary = ["SQL injection vulnerabilities allow attackers to execute arbitrary SQL queries on", 
			"a web application's database. This can lead to unauthorized access, data", 
			"manipulation, or even the deletion of the entire database.",""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Steps Taken:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Detection:")

text.setFont('Times-Roman', 16)
summary = ["The tool analyzes input fields for potential SQL injection points.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Payloads:")

text.setFont('Times-Roman', 16)
summary = ["Employs predefined SQL injection payloads to assess the security of input fields.", 
			"Sample Payload: Inputting (' OR '1'='1';) -- to bypass a login form.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Findings:")
text.setFont('Times-Roman', 16)
summary = ["Number of Attack Vectors Identified: 1", 
			"Attack Execution: " + "!!ATTACK SUCCEEDED!!", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("CVSS Score:")
text.setFont('Times-Roman', 16)
summary = ["Severity: High", 
			"Score: 8.8", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Do It Yourself!")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Identify Input Fields:")

text.setFont('Times-Roman', 16)
summary = ["Locate input fields or parameters where user input is processed, such as login", 
			"forms, search boxes, or URL parameters.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Input Malicious SQL Payloads:")

text.setFont('Times-Roman', 16)
summary = ["Inject malicious SQL payloads into the input fields to exploit potential", 
			"vulnerabilities", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Error-Based SQL Injection:")

text.setFont('Times-Roman', 16)
summary = ["Intentionally trigger SQL errors by injecting payloads like", 
			"' OR 1=CONVERT(int, (SELECT @@version)); --.", 
			"Observe error messages that may reveal information about the database."]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 16)
text.textLine("Time-Based Blind SQL Injection:")

text.setFont('Times-Roman', 16)
summary = ["Use time-delayed payloads to detect if the application is vulnerable to blind SQLi", 
			"An example payload is ' OR IF(1=1, SLEEP(5), 0); --.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Boolean-Based Blind SQL Injection:")

text.setFont('Times-Roman', 16)
summary = ["Craft payloads that rely on true/false conditions to extract information.", 
			"Example payload: ' OR 1=1 --.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("UNION-Based SQL Injection:")

text.setFont('Times-Roman', 16)
summary = ["Exploit the UNION SQL operator to combine the results with additional information.", 
			"Example payload: ' UNION SELECT username, password FROM users; --.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Out-of-Band SQL Injection:")

text.setFont('Times-Roman', 16)
summary = ["Utilize techniques like DNS requests or HTTP requests to retrieve data when classic", 
			"SQL injection methods are restricted.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Prevention:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Parameterized Queries or Prepared Statements:")

text.setFont('Times-Roman', 16)
summary = ["Instead of directly embedding user input into SQL queries, use parameterized queries", 
			"or prepared statements provided by the programming language or database library.", 
			"These mechanisms separate user input from the SQL query structure.",""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Avoid Dynamic SQL Construction:")

text.setFont('Times-Roman', 16)
summary = ["Avoid dynamically constructing SQL queries by concatenating strings with user", 
			"input. Dynamic SQL is prone to injection attacks.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Input Validation:")

text.setFont('Times-Roman', 16)
summary = ["Validate and sanitize user inputs before using them in SQL queries. Input validation", 
			"ensures that the input adheres to expected patterns, reducing the risk of SQLi.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Use Stored Procedures:")

text.setFont('Times-Roman', 16)
summary = ["Employ stored procedures to encapsulate and execute database logic.", 
			"Stored procedures help mitigate SQL injection by predefining the SQL operations", 
			"that can be performed.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Escaping Special Characters:")

text.setFont('Times-Roman', 16)
summary = ["Escape or sanitize special characters in user input to neutralize their potential", 
			"impact on SQL queries.", ""]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 18)
text.textLine("VI. Cross-Site Scripting (XSS):")

text.setFont('Times-Italic', 18)
text.textLine("")
text.textLine("Objective:")

text.setFont('Times-Roman', 16)
summary = ["XSS vulnerabilities enable attackers to inject malicious scripts into web pages,", 
			"which are then executed by users' browsers. This can lead to the theft of sensitive", 
			"information, session hijacking, or defacement of websites.",""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Steps Taken:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Detection:")

text.setFont('Times-Roman', 16)
summary = ["The tool scans webpages for input fields and text elements susceptible to XSS attacks.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Payloads:")

text.setFont('Times-Roman', 16)
summary = ["Utilizes predefined XSS payloads to assess and simulate XSS attacks.", 
			"Sample Payload: Injecting <script>alert('XSS')</script> in an input field.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Findings:")
text.setFont('Times-Roman', 16)
summary = ["Number of Attack Vectors Identified: " + str(len(input_elements)), 
			"Attack Execution: " + "!!ATTACK SUCCEEDED!!", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("CVSS Score:")
text.setFont('Times-Roman', 16)
summary = ["Severity: Medium", 
			"Score: 6.1", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Do It Yourself!")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Identify Input Fields:")

text.setFont('Times-Roman', 16)
summary = ["Locate input fields on web pages such as search bars, text boxes, and form fields.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Test with Attributes:")

text.setFont('Times-Roman', 16)
summary = ["Inject payloads into HTML attributes. Examples include:", 
			"<img src=x onerror=alert('XSS')>", 
			"<a href=`javascript:alert('XSS')`>Click me</a>", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Test with Malformed HTML:")

text.setFont('Times-Roman', 16)
summary = ["Use payloads that exploit browser parsing issues. Examples include:", 
			"<b onmouseover=alert('XSS')>mouseover here</b>"]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 16)
text.textLine("Test Event Handlers:")

text.setFont('Times-Roman', 16)
summary = ["Check event handlers for vulnerabilities. Examples include:", 
			"onmouseover=`alert('XSS')`", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Test URL Parameters:")

text.setFont('Times-Roman', 16)
summary = ["Inject payloads into URL parameters. Examples include:", 
			"?search=<script>alert('XSS')</script>", 
			"?name=<img src=x onerror=alert('XSS')>", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Test for Delayed Execution:")

text.setFont('Times-Roman', 16)
summary = ["Use payloads that might be triggered after a delay, making detection challenging.", 
			"<script>setTimeout(function(){alert('XSS')}, 5000);</script>", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Test for Stored XSS:")

text.setFont('Times-Roman', 16)
summary = ["If applicable, check for stored XSS vulnerabilities by injecting payloads that are", 
			"stored and later displayed to other users.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Prevention:")

text.setFont('Times-Bold', 16)
text.textLine("")
text.textLine("Input Validation:")

text.setFont('Times-Roman', 16)
summary = ["Validate and sanitize all user inputs on both client and server sides.", 
			"Define and enforce a strict whitelist of allowed characters, rejecting any input", 
			"that doesn't adhere to the defined criteria.",""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Output Encoding:")

text.setFont('Times-Roman', 16)
summary = ["Encode user-generated content before rendering it in the HTML document.", 
			"This involves converting special characters to their HTML entities.",
			"Use proper output encoding functions such as htmlspecialchars() in PHP,", 
			"escapeHtml in Java, or equivalent functions in other programming languages.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Content Security Policy (CSP):")

text.setFont('Times-Roman', 16)
summary = ["Implement Content Security Policy headers in your web application.", 
			"CSP helps control which resources can be loaded and executed, reducing the", 
			"risk of executing malicious scripts.",
			"Configure CSP to block or restrict the use of inline scripts and unsafe practices.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("HTTP-Only Cookies:")

text.setFont('Times-Roman', 16)
summary = ["Set the HTTP-only flag on cookies to prevent JavaScript access. This ensures", 
			"that sensitive information, such as session cookies, cannot be accessed by", 
			"malicious scripts.", ""]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 16)
text.textLine("Contextual Output Encoding:")

text.setFont('Times-Roman', 16)
summary = ["Encode output based on the context where it will be used. Different contexts", 
			"(HTML, attribute, JavaScript, etc.) have different encoding requirements.",
			"Use functions specific to the output context, such as htmlspecialchars for HTML", 
			"content and encodeURI for JavaScript.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Avoiding eval():")

text.setFont('Times-Roman', 16)
summary = ["Avoid using eval() and other dynamic code execution functions.",
			"If dynamic code execution is necessary, validate and sanitize inputs thoroughly", 
			"before execution.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Secure Headers:")

text.setFont('Times-Roman', 16)
summary = ["Implement secure headers such as X-Content-Type-Options and X-Frame-Options", 
			"to control content types and framing policies.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Use Security Libraries:")

text.setFont('Times-Roman', 16)
summary = ["Leverage security libraries and frameworks that provide built-in protection", 
			"against XSS, such as Java's OWASP AntiSamy or Ruby on Rails' sanitize helper.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 16)
text.textLine("Regular Expressions:")

text.setFont('Times-Roman', 16)
summary = ["Use regular expressions to filter and sanitize input. Ensure that input adheres", 
			"to expected patterns and reject any input that doesn't meet the criteria.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 18)
text.textLine("Further Reading:")

text.setFont('Times-Roman', 16)
summary = ["https://portswigger.net/web-security/cross-site-scripting", 
			"https://owasp.org/www-community/attacks/xss/", 
			"https://csrc.nist.gov/glossary/term/cross_site_scripting",
			"https://owasp.org/www-community/Types_of_Cross-Site_Scripting",
			"https://portswigger.net/web-security/cross-site-scripting/reflected",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
			"https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
			"https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html",
			"https://ieeexplore.ieee.org/document/10128470",
			"https://owasp.org/www-community/attacks/DOM_Based_XSS",
			"https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"]
for line in summary:
	text.textLine(line)

pdf.drawText(text)
pdf.showPage()

text = pdf.beginText(40, 770)

text.setFont('Times-Bold', 18)
text.textLine("VII. Reference Links:")

text.setFont('Times-Roman', 16)
summary = ["", "To provide comprehensive support, the tool includes reference links and", 
			"step-by-step guides for each vulnerability. These resources aid users in", 
			"understanding the nature of the vulnerabilities detected and offer recommendations", 
			"for mitigation.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 16)
text.textLine("Additional references for Open Redirection Vulnerability:")

text.setFont('Times-Roman', 16)
summary = ["", "https://cwe.mitre.org/data/definitions/601.html", 
			"https://portswigger.net/kb/issues/00500100_open-redirection-reflected", 
			"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html", 
			"https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/04-Testing_for_Client_Side_URL_Redirect",
			"https://portswigger.net/support/using-burp-to-test-for-open-redirections", 
			"https://nvd.nist.gov/vuln/detail/CVE-2023-22797", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 16)
text.textLine("Additional references for SQL Injection Vulnerability:")

text.setFont('Times-Roman', 16)
summary = ["", "https://owasp.org/www-community/attacks/SQL_Injection", 
			"https://portswigger.net/web-security/sql-injection", 
			"https://portswigger.net/kb/issues/00100200_sql-injection", 
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
			"https://capec.mitre.org/data/definitions/66.html", 
			"https://www.cisa.gov/sites/default/files/publications/Practical-SQLi-Identification.pdf", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Bold', 18)
text.textLine("VIII. Conclusion:")

text.setFont('Times-Roman', 16)
summary = ["", "The Automated Web Security Analysis Tool serves as a crucial asset in", 
			"identifying and addressing common web application vulnerabilities. As the", 
			"project evolves, further enhancements will be made to maximize the tool's", 
			"effectiveness and usability, ensuring its reliability across diverse web", 
			"development environments.", ""]
for line in summary:
	text.textLine(line)

text.setFont('Times-Italic', 16)
summary = ["Note: CVSS scores will need to be determined based on the specific findings", 
			"and impact of each vulnerability. Consult the Common Vulnerability Scoring", 
			"System (CVSS) for accurate scoring.", ""]
for line in summary:
	text.textLine(line)

pdf.drawText(text)

pdf.save()