from flask_restx import Namespace, fields


class CampaignDto:
    api = Namespace('campaign', description='Campaign Rest Api')

    ttp_search = api.model('Ttp Events Search', {
        'ttp': fields.String
    })

    gui_search = api.model('Gui Events Search', {
        'gui': fields.String
    })

    file_search = api.model('Png Events Search', {
        'country': fields.String,
        'time': fields.String
    })

    test_params = api.model('Domain Test', {
        'params': fields.String
    })

    attack_table_params = api.model('Attack Table Params', {
        'group': fields.Boolean,
        'country': fields.Boolean,
        'year': fields.Boolean
    })
