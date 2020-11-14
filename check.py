import requests
import os
import json
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

ports = os.environ.get('PORTS')
urls = ['https://{0}'.format(os.environ.get('DOMAIN'))]
try:
    ports = ports.strip(' ').split(',')
    for port in ports:
        urls.append('http://{0}:{1}'.format(os.environ.get('DOMAIN'), port))
except:
    pass
vuln_id = os.environ.get('VULN_ID')


def resp(state=False, url='https://{0}/'.format(os.environ.get('DOMAIN'))):
    if state:
        return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": url})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": url})


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
    'manager'
]

good_to_have = [
    'login',
    'password'
]

stop_words = [
    'bad',
    'found',
    'available',
    'cannot',
    'forbidden',
    'restricted',
]

stop_content_types = [
    'json',
    'text/plain'
]


stop_words_path = []

for url in urls:
    for path in path_list:
        # TODO: think about it
        stop_words_path.append(f'{url}{path}')
        stop_words_path.append(f'{path}')


def prepare_requests(url):
    result = []
    for path in path_list:
        result.append(f'{url}{path}')
    return result


def resp(state=False, description=urls[0]):
    if state:
        return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": description})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": description})


def check():
    for url in urls:
        candidates = prepare_requests(url)
        try:
            for candidate in candidates:
                candidate_score = 0
                # TODO: redirects are important
                response = requests.get(candidate, timeout=4, verify=False, allow_redirects=True)
                if response.status_code >= 400:
                    return resp(False, candidate)
                if any([stop_content_type in response.headers.get('Content-Type').lower() for stop_content_type in stop_content_types]):
                    return resp(False, candidate)
                for admin_pattern in admin_patterns:
                    if response.text.lower().find(admin_pattern) > -1:
                        candidate_score += 15
                        for good_pattern in good_to_have:
                            if response.text.lower().find(good_pattern) > -1:
                                candidate_score += 5
                for stop_word in stop_words:
                    if response.text.lower().find(stop_word) > -1:
                        candidate_score -= 55
                print(candidate_score)
                if candidate_score >= 5:
                    return resp(True, candidate)
            return resp(False)
        except Exception as ex:
            pass
    return resp(False)


if __name__ == '__main__':
    print(check())
