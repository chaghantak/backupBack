from flask_restx import Namespace, fields


class CallTestDto:
    api = Namespace('call', description='Call Rest Api')

    domain_convert_params = api.model('Domain Convert Params', {
        'type': fields.String,
        'param': fields.String(required=False)
    })

    domain_distance_params = api.model('Domain Distance Params', {
        'type': fields.String,
        'param': fields.String
    })
