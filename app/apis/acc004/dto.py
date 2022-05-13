from flask_restx import Namespace, fields


class Acc004Dto:
    api = Namespace('ui-acc-004', description='UI-ACC-002 Rest Api')

    model_params = api.model("모델 관련 Params", {
        'ttp_type': fields.String(required=False),
        'algorithm_type': fields.String(required=False),
        'domain_type': fields.String(required=False)
    })
