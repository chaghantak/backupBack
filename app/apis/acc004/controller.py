from flask import request
from flask_restx import Resource

from .dto import Acc004Dto

api = Acc004Dto.api


@api.route('/')
class Acc004(Resource):
    def get(self):
        """
        받아서 web socket 으로 view 쪽으로 전달 해야함
        :return:
        """
        pass


@api.route('/<train_type>')
class Acc044Put(Resource):
    @api.expect(Acc004Dto.model_params)
    def put(self, train_type):
        """
        모델 학습 관련 Api 테스트 용 URL
        :return:
        """
        print(train_type)
        pass
