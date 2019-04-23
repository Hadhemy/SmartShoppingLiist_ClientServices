import json
import unittest
from flask import request, Flask, current_app
from userservice import app
# set our application to testing mode
from userservice.myservices.users.routes import users
app.register_blueprint(users)

app.testing = True
app_context = app.app_context()
#app_context.push()

@users.route('/user')
class TestApi(unittest.TestCase):


    def test_add(self):
        json_data = request.get_json()
        firstname = json_data['firstname']
        lastname = json_data['lastname']
        email = json_data['email']
        phone_number = json_data['phone_number']
        password = json_data['password']
        account_created_at = json_data['account_created_at']
        isLogged = True
        with  app.app_context():
             #resp = client.get('/user')

             self.client = app.test_client()
             # send data as POST form to endpoint
             sent = client.post ('/user',
                            json={ "firstname": "samiraz", "lastname": "zahra ", "email": "azahrasamzzza1@gmail.com",
                                   "phone_number": "11100766", "password": "saam211",
                                   "account_created_at": "03/15/2019" })
             json_data = sent.get_json()
        # check result from server with expected data


if __name__ == "__main__":
    unittest.main()