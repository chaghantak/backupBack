from flask import request
from flask_restx import Resource

from .dto import CallTestDto

api = CallTestDto.api


@api.route('/domain-convert')
class DomainConvertApi(Resource):
    @api.expect(CallTestDto.domain_convert_params)
    def post(self):
        pass
