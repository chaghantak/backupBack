from flask_restx import Api
from flask import Blueprint

from .chain.controller import api as chain_ns
from .campaign.controller import api as campaign_ns
from .acc002.controller import api as acc002_ns
from .acc003.controller import api as acc003_ns
from .acc004.controller import api as acc004_ns

api_bp = Blueprint('apis', __name__)

api = Api(api_bp, title='APIS', description='APT Rest Api Server')

# chain 관련
api.add_namespace(chain_ns)

# campaign 관련
api.add_namespace(campaign_ns)

# ui-acc-002 관련
api.add_namespace(acc002_ns)

# ui-acc-003 관련
api.add_namespace(acc003_ns)

# ui-acc-004 관련
api.add_namespace(acc004_ns)
