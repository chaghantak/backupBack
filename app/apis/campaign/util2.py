import datetime


class TacticCollection:
    navigator = {
        "reconnaissance": 1,
        "resource-development": 2,
        "initial-access": 3,
        "execution": 4,
        "persistence": 5,
        "privilege-escalation": 6,
        "defense-evasion": 7,
        "credential-access": 8,
        "discovery": 9,
        "lateral-movement": 10,
        "collection": 11,
        "command-and-control": 12,
        "exfiltration": 13,
        "impact": 14,
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
                'ttps': params[4]}


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
