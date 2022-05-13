from flask import request
from flask_restx import Resource

from .dto import Acc002Dto

api = Acc002Dto.api


@api.route('/')
class Acc002(Resource):
    def get(self):
        """
        받아서 web socket 으로 view 쪽으로 전달 해야함
        :return:
        """
        pass


@api.route('/<btn_name>')
class Acc002Put(Resource):
    @api.expect(Acc002Dto.tag_params)
    def put(self, btn_name):
        """
        태그 관련 Api 테스트 용 URL
        :return:
        """
        params = request.get_json()
        print(btn_name)
        print(params)
        pass
