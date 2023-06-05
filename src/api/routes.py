"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
import bcrypt


api = Blueprint('api', __name__)

#añadir /api/  antes del login en el postman


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200
    
@api.route('/login', methods=['POST'])
def register():
    body = request.get_json()
    hashed = bcrypt.hashpw(body['password'].encode(), bcrypt.gensalt(14))
    print(hashed)
    new_user = User(body['email'], hashed.decode())
    db.session.add(new_user)
    db.session.commit()
    return jsonify(new_user.serialize()), 201


#login 
@api.route('/login', methods=['POST'])
def login():
    body = request.get_json()
    token = Controller.login(body)
    if token.get('token'):
        return jsonify(token),200
    return jsonify(token),token['status']

def login(body):
    user_verify = verify_user_email_and_pass(body)
    if user_verify.get('error') is not None:
        return user_verify
    user = Repository.get_user_by_email(body['email'])
    if user is None:
        return {"msg": "User not found", "error": True, "status": 404}
    if bcrypt.checkpw(body['password'].encode(), user.password.encode()):
        user_serialize = user.serialize()
        new_token = create_access_token(identity=user.serialize())
        rol = user_serialize['user_rol']['rol_type']
        return {"token": new_token,"rol": rol}
    return {"msg": "User not found", "error": True, "status": 404 }  


#register_client

@api.route('/register/client', methods=['POST'])
def create_user():
    body = request.get_json()
    user = Controller.create_user(body,"client")
    if isinstance(user, User):
        return jsonify(user.serialize()), 200
    return jsonify(user)

def create_user(new_user,rol_type):
    user_verify = verify_user_email_and_pass(new_user)
    if user_verify.get('error') is not None:
        return user_verify
    hashed = bcrypt.hashpw(new_user['password'].encode(), bcrypt.gensalt(14))
    user_rol_id = User_rol.query.filter_by(rol_type=rol_type).first()

    return Repository.create_user(new_user['email'], hashed.decode(), new_user['name'], new_user['last_name'], user_rol_id.id)

    def create_user(email, password, name, last_name, user_rol_id):
    new_user = User(email = email, password=password, name=name, last_name= last_name, user_rol_id = user_rol_id)
    db.session.add(new_user)
    db.session.commit()
    return new_user