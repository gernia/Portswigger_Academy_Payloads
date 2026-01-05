
## Unprotected functionality

- look up `robots.txt` and JavaScript files to see if URLs are leaked

## Parameter-based access control

- parameters with access rights could be stored in
	- a hidden field
	- a cookie
	- a preset query string parameter


## URL-based access control

- access to `/admin` blocked by front-end
- send request with URL set to `/` and `X-Original-URL` set to `/admin`
- send request with URL set to `/?username=carlos` and `X-Original-URL` header set to `/admin/delete`

## Method-based access control

- function to make users admin accepts other methods than `POST`
- change method from `POST` to `POSTX` 
- convert request to `GET`, change username parameter


## Insecure direct object references (IDOR)

- access files from other users without permission
- chatbot transcript download for my user: `GET /download-transcript/2.txt 
- change it to `GET /download-transcript/1.txt` to download transcript from other user


## Multi-step process with no access control on one step

- see if single steps in a multi-step process can be sent without access control


## Referer-based access control

- referer header may be used to prevent unauthorized access to certain endpoints
- capture valid promotion request to get referer header: ``/admin-roles?username=wiener&action=upgrade``
- other example:
    - `GET /admin?delete?user=xxx`
    - Referer: https://vulnerable-app.com/admin
