import requests
from CryptoHelper import md5_hash
from DevicesService import DevicesService
import logging

logger = logging.getLogger(__name__)

class UserService:
    def __init__(self, device: DevicesService):
        self._device = device
        self._token = ''
        self.user_title = ''

    def login(self, username: str, password: str):
        url = self.get_absolute_url('/api/users/login')
        headers = self._device.create_headers()
        data = {
            'UserName': username,
            'PasswordHash': md5_hash(password)
        }

        try:
            response = requests.post(url, json=data, headers=headers, timeout=10, verify=False)
            logger.info(f"پاسخ لاگین: کد وضعیت {response.status_code}, محتوا: {response.text}")
            if response.status_code in (200, 201):
                try:
                    json_data = response.json()
                    self._token = json_data.get('Token', '')
                    self.user_title = json_data.get('Title', 'Unknown')
                except ValueError as e:
                    logger.error(f"خطا در تجزیه JSON: {str(e)}, پاسخ: {response.text}")
                    raise Exception(f"پاسخ سرور JSON معتبر نیست: {response.text}")
            else:
                try:
                    error_message = response.json().get('Message', response.text)
                except ValueError:
                    error_message = response.text
                raise Exception(f"خطا در لاگین: {error_message}")
        except requests.RequestException as e:
            logger.error(f"خطا در درخواست لاگین: {str(e)}")
            raise Exception(f"خطا در اتصال به سرور: {str(e)}")

    def logout(self):
        self._token = ''
        self.user_title = ''

    def get_absolute_url(self, endpoint: str):
        return self._device.get_absolute_url(endpoint)

    def create_headers(self):
        headers = self._device.create_headers()
        if self._token:
            headers['Authorization'] = f'Bearer {self._token}'
        return headers


