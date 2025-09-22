from urllib import parse


class Configuration:
    def __init__(self, base_url: str, api_version: str):
        self._base_url = base_url
        self._generation_version = api_version

    def get_absolute_url(self, endpoint: str):
        return parse.urljoin(self._base_url, endpoint)

    def create_headers(self):
        headers = {
            'GenerationVersion': self._generation_version,
        }
        return headers
