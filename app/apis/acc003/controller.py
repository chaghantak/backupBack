from flask import request
from flask_restx import Resource

from .dto import Acc003Dto

api = Acc003Dto.api


@api.route('/trans/<alg_name>')
class Trans(Resource):
    @api.expect(Acc003Dto.trans_params)
    def put(self, alg_name):
        """
        태그 관련 Api 테스트 용 URL
        :return:
        """
        params = request.get_json()
        print(alg_name)
        print(params)
        pass


@api.route('/sim/<alg_name>')
class Sim(Resource):
    def put(self, alg_name):
        pass
