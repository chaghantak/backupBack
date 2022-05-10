from flask import Flask
from flask_pymongo import PyMongo
from flask_sqlalchemy import SQLAlchemy
from neo4j import GraphDatabase

from .extensions import cors, socketio
from database.mongo import mongo
from database.postgres import postgresql
from database.neo4j import neo4j


def create_app():
    app = Flask(__name__)

    register_extensions(app)

    from .apis import api_bp

    app.register_blueprint(api_bp, url_prefix='/apt/apis')

    return app


def register_extensions(app):
    app.config['JSON_AS_ASCII'] = False         # jsonify 사용시 한글 깨짐 방지
    app.config['SECRET_KEY'] = 'secret!'        # key
    cors.init_app(app)
    # socket push 서버는 따로 분리를 하는게 좋을까?
    # socket push + kafka consumer 프로젝트 구성 ?
    socketio.init_app(app)

    # TODO 이후에 config 파일로 빼자
    chain_db = PyMongo(app, uri='mongodb://root:mongodb@192.168.0.11:27017/chain_eval?authSource=admin')
    chain_2021_db = PyMongo(app, uri='mongodb://root:mongodb@192.168.0.11:27017/chain_2021?authSource=admin')
    mitre_enterprise_attack_db = PyMongo(app, uri='mongodb://root:mongodb@192.168.0.11:27017/mitre-enterprise-attack?authSource=admin')
    mitre_shield_db = PyMongo(app, uri='mongodb://root:mongodb@192.168.0.11:27017/mitre-shield?authSource=admin')
    mongo['chain'] = chain_db
    mongo['chain_2021'] = chain_2021_db
    mongo['mitre_enterprise_attack'] = mitre_enterprise_attack_db
    mongo['mitre_shield'] = mitre_shield_db

    # flask sqlalchemy 로 관리 가능한 디비가 여러개 일 경우 bind 로 관리를 해야함
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://jiapp:jiapp@192.168.0.11:5432/classification_dummy'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    postgresql_db = SQLAlchemy(app)
    postgresql['classification_dummy'] = postgresql_db

    neo4j_chain_db = GraphDatabase.driver('bolt://192.168.0.16:7687', auth=('neo4j', 'jiin0701!'))
    neo4j['chain'] = neo4j_chain_db
