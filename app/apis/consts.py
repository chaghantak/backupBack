class IndexConst:
    WINLOG_BEAT = 'winlogbeat'
    FILE_BEAT = 'filebeat'
    AUDIT_BEAT = 'auditbeat'


class EventCategoryConst:
    PROCESS = 'process'
    NETWORK = 'network'
    NETWORK_TRAFFIC = 'network_traffic'
    FILE = 'file'
    REGISTRY = 'registry'
    CONFIGURATION = 'configuration'
    AUTHENTICATION = 'authentication'
    IAM = 'iam'
    WEB = 'web'
    INTRUSION_DETECTION = 'intrusion_detection'
    SESSION = 'session'
    SERVICE = 'service'
    SCHEDULED = "scheduled"


class EventTypeConst:
    START = 'start'
    END = 'end'
    INFO = 'info'
    CHANGE = 'change'
    ACCESS = 'access'
    CONNECTION = 'connection'
    PROTOCOL = 'protocol'
    CREATION = 'creation'
    DELETION = 'deletion'
    ADMIN = 'admin'
    USER = 'user'
    ALLOWED = 'allowed'


class EventCodeConst:
    CODE_8 = '8'
    CODE_19 = '19'
    CODE_20 = '20'
    CODE_21 = '21'
    CODE_4624 = '4624'
    CODE_4648 = '4648'
    CODE_4663 = '4663'
    CODE_4697 = '4697'
    CODE_4698 = '4698'
    CODE_4720 = '4720'
    CODE_4848 = '4848'
    CODE_5140 = '5140'
    CODE_5861 = '5861'


class EventActionConst:
    LOGGED_IN = 'logged-in'
    LOGGED_IN_EXPLICIT = 'logged-in-explicit'
    SERVICE_INSTALLED = 'service-installed'
    SCHEDULED_TASK_CREATED = 'scheduled-task-created'


class KeyConst:
    SOURCE = 'source'
    EVENT = 'event'
    PROCESS = 'process'
    HOST = 'host'
    FILE = 'file'
    NETWORK = 'network'
    REGISTRY = 'registry'
    DESTINATION = 'destination'
    WINLOG = 'winlog'
    USER = 'user'
    CLIENT = 'client'
    SERVER = 'server'
    HTTP = 'http'
    URL = 'url'
    USER_AGENT = 'user_agent'
    RULE = 'rule'
    INDEX = '_index'


class ChainCollection:
    APT291_CHAINS = 'apt291_chains'
    APT291_EVENTS = 'apt291_events'
    APT292 = 'apt292'
