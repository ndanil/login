from requests import get, post

print(get('http://127.0.0.1:5000/api/user/7').json())
