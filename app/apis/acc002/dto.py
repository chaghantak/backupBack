from flask_restx import Namespace, fields


class Acc002Dto:
    api = Namespace('ui-acc-002', description='UI-ACC-002 Rest Api')

    tag_params = api.model('태그 관련 Params', {
        'overwrite': fields.Boolean(required=False),
        'ttp_idx': fields.Integer(requiree=False),
        'ttp_content': fields.String(requiree=False)
    })
