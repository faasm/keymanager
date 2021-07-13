import requests
import json

host = "localhost"
registry_port = 5000
user = "demo"
func = "hello"

def load_policy():
    with open("tests/policy.json") as policy_file:
        policy = json.load(policy_file)
    return policy

###############################################################################
# TESTS #######################################################################
###############################################################################

def test_connection():
     response = requests.get("http://{}:{}/".format(host, registry_port))
     assert response.status_code == 200
     assert response.text == 'KeyManager for faasm'

def test_register():
    response = requests.post("http://{}:{}/api/v1/registry/register/{}".format(host, registry_port, user), json=load_policy())
    assert response.status_code == 200

def test_prerequest():
    key="whatever"
    register_msg = {"key": key}
    response = requests.post("http://{}:{}/api/v1/registry/pre-request/{}/{}".format(host, registry_port, user, func),json=register_msg)
    assert response.status_code == 200
