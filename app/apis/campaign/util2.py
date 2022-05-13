import datetime


class TacticCollection:
    navigator = {
        "reconnaissance": 1,        #TA0043
        "resource-development": 2,  #TA0042
        "initial-access": 3,        #TA0001
        "execution": 4,             #TA0002
        "persistence": 5,           #TA0003
        "privilege-escalation": 6,  #TA0004
        "defense-evasion": 7,       #TA0005
        "credential-access": 8,     #TA0006
        "discovery": 9,             #TA0007
        "lateral-movement": 10,     #TA0008
        "collection": 11,           #TA0009
        "command-and-control": 12,  #TA0011
        "exfiltration": 13,         #TA0010
        "impact": 14,               #TA0040
    }

    navi = {
        "reconnaissance": 'TA0043',
        "resource-development": 'TA0042',
        "initial-access": 'TA0001',
        "execution": 'TA0002',
        "persistence": 'TA0003',
        "privilege-escalation": 'TA0004',
        "defense-evasion": 'TA0005',
        "credential-access": 'TA0006',
        "discovery": 'TA0007',
        "lateral-movement": 'TA0008',
        "collection": 'TA0009',
        "command-and-control": 'TA0011',
        "exfiltration": 'TA0010',
        "impact": 'TA0040',
    }


class DictMaker:
    def __init__(self, params):
        self.params = params

    def tacticmaker(self, params):
        return {'id': params['ttp'].split('.')[0],
                'name': params['tactic_name'],
                'techniques': []}

    def techmaker(self, params):
        return {'id': params['ttp'].split('.')[1],
                'name': params['technique_name'],
                'subTechniques': []}

    def subtechmaker(self, params):
        if params['subtechnique_name']:
            return {'id': params['ttp'].split('.')[2],
                    'name': params['subtechnique_name']}
        else:
            return ""

    def columnsmaker(self, params):
        return {'group': params[1],
                'year': params[2],
                'country': params[3],
                'ttps': params[4],
                'index': int(params[5])}


def week_count():
    kst = datetime.timezone(datetime.timedelta(hours=9))
    today = datetime.datetime(int(datetime.datetime.now().strftime("%Y")),
                              int(datetime.datetime.now().strftime("%m")),
                              int(datetime.datetime.now().strftime("%d")),
                              int(datetime.datetime.now().strftime("%H")),
                              int(datetime.datetime.now().strftime("%M")),
                              int(datetime.datetime.now().strftime("%S")), tzinfo=kst)
    week = today - datetime.timedelta(days=7)
    return week


def sorted_tactic(list_data):
    navigator = TacticCollection.navigator
    for num in range(len(list_data)):
        if list_data[num]['name'] in navigator:
            list_data[num]['sorted_num'] = navigator[list_data[num]['name']]
    sort_list = sorted(list_data, key=lambda item: item['sorted_num'])
    return sort_list

def sorted_option(result, params):
    result = sorted(result, key=lambda item: (item["country"] if params["country"] else None,
                                            item["group"] if params["group"] else None,
                                            item["year"] if params["year"] else None))
    return result
