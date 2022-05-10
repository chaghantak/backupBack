from flask import request
from flask_restx import Resource

from .dto import ChainDto
from .service import ChainService
from utils.logger import Logger


logger = Logger.get_logger(__name__)
api = ChainDto.api


@api.route('/events-matrix')
class Events(Resource):
    @api.expect(ChainDto.events_search)
    def post(self):
        """
        events_new DB 에서 항목을 읽어 matrix 구조를 json 형태로 리턴
        :return:
        """
        params = request.get_json()

        return ChainService.get_events(params)


@api.route('/events-ttp')
class EventsByTtp(Resource):
    @api.expect(ChainDto.ttp_search)
    def post(self):
        """
        ttp 정보로 해당 되는 event 목록을 조회
        host 검색을 했을 경우 host 정보도 같이 넘겨 줘야 함
        :return:
        """
        params = request.get_json()

        return ChainService.get_events_ttp(params)


@api.route('/events-id')
class EventsById(Resource):
    @api.expect(ChainDto.id_search)
    def post(self):
        """
        event id 값으로 해당 event 를 상세 조회
        _index, event.category, event.type 별로 구분 하여 리턴
        :return:
        """
        params = request.get_json()

        return ChainService.get_events_id(params)


@api.route('/neo-chain-id')
class NeoChainById(Resource):
    @api.expect(ChainDto.id_search)
    def post(self):
        """
        event id 값으로 neo4j chain 데이터 조회
        :return:
        """
        params = request.get_json()

        return ChainService.get_neo_chain_id(params)


# @api.route('/test')
# class TestChainById(Resource):
#     @api.expect(ChainDto.test_search)
#     def post(self):
#         """
#         test
#         :return:
#         """
#         params = request.get_json()
#
#         return ChainService.get_test_chain_id(params)