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
