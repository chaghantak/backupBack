from flask_restx import Namespace, fields


class Acc003Dto:
    api = Namespace('ui-acc-003', description='UI-ACC-003 Rest Api')

    trans_params = api.model('변환 관련 Params', {
        'select_indices': fields.List(fields.Integer),
        'ttp_type': fields.String(requiree=False),
        'param1': fields.Integer(requiree=False)
    })
