import json


class Formatter:
    def format(self, record):
        return json.dumps({"message": record})
