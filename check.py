import requests
import os
import json

payload = 'kek.kek'
xss_payload = 'kek.kek"onload="alert();'

url = 'https://{0}'.format(os.environ.get('DOMAIN'))
vuln_id = os.environ.get('VULN_ID')

path_list = [
    '/admin',
    '/administrator',
    '/phpmyadmin',
    '/pmadmin',
    '/myadmin',
    '/django',
    '/private',
    '/superuser',
    '/manager',
    '/management',
    '/uvpanel'
]

admin_patterns = [
    'admin',
    'administrator',
    'django',
    'manager',
]

stop_words = [
    '404',
    'not found',
    '403',
    'unavailable'
]

stop_words_path = stop_words

for path in path_list:
    stop_words_path.append(f'{url}{path}')


def prepare_requests():
    result = []
    for path in path_list:
        result.append(f'{url}{path}')
    return result


def resp(state=False, description=url):
    if state:
        return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": description})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": description})


def check():
    if not url:
        return resp(False)

    candidates = prepare_requests()
    try:
        for candidate in candidates:
            candidate_score = 0
            response = requests.get(candidate, timeout=4)
            for admin_pattern in admin_patterns:
                if response.text.find(admin_pattern) > -1:
                    candidate_score += 15
            for stop_word in stop_words:
                if response.text.find(stop_word) > -1:
                    candidate_score -= 15
            for stop_word in stop_words_path:
                if response.text.find(stop_word) > -1:
                    candidate_score -= 5
            if candidate_score >= 5:
                return resp(True, candidate)
        return resp(False)
    except Exception as ex:
        pass
    return resp(False)


if __name__ == '__main__':
    print(check())
