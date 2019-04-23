from flask import Blueprint

api = Blueprint('api', __name__)

@api.route('/getStuff')
def getStuff():
    return '{"result" : "You are in da API!!"}'

