from flask_restx import Api
from flask import Blueprint

from .chain.controller import api as chain_ns
from .campaign.controller import api as campaign_ns
from .calltest.controller import api as calltest_ns

api_bp = Blueprint('apis', __name__)

api = Api(api_bp, title='APIS', description='APT Rest Api Server')

# chain 관련
api.add_namespace(chain_ns)

# campaign 관련
api.add_namespace(campaign_ns)

# call test 관련
api.add_namespace(calltest_ns)
