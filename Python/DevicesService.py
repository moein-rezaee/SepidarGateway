from base64 import b64encode
from uuid import uuid4
import requests
from Configuration import Configuration
from CryptoHelper import aes_encrypt, aes_decrypt, rsa_encrypt
import logging

logger = logging.getLogger(__name__)

class DevicesService:
    def __init__(self, config: Configuration, code: str):
        self._config = config
        self._registration_code = code
        self._integration_id = code[0:4]
        self._public_key = ''
        self.DeviceName = ''

    def register(self):
        url = self.get_absolute_url('/api/Devices/Register/')
        aes_key = self._registration_code * 2
        encrypted_data = aes_encrypt(aes_key, self._integration_id)
        data = {
            'Cypher': encrypted_data['cipher'],
            'IV': encrypted_data['iv'],
            'IntegrationID': self._integration_id
        }

        try:
            response = requests.post(url, json=data, timeout=10, verify=False)
            logger.info(f"پاسخ ثبت دستگاه: کد وضعیت {response.status_code}, محتوا: {response.text}")
            if response.status_code in (200, 201):
                try:
                    json_data = response.json()
                    self._public_key = aes_decrypt(aes_key, json_data['Cypher'], json_data['IV']).decode('utf-8')
                    self.DeviceName = json_data.get('DeviceTitle', 'Unknown')
                except ValueError as e:
                    logger.error(f"خطا در تجزیه JSON: {str(e)}, پاسخ: {response.text}")
                    raise Exception(f"پاسخ سرور JSON معتبر نیست: {response.text}")
            else:
                try:
                    error_message = response.json().get('Message', response.text)
                except ValueError:
                    error_message = response.text
                raise Exception(error_message)
        except requests.RequestException as e:
            logger.error(f"خطا در درخواست ثبت دستگاه: {str(e)}")
            raise Exception(f"خطا در اتصال به سرور: {str(e)}")

    def get_absolute_url(self, endpoint: str):
        return self._config.get_absolute_url(endpoint)

    def create_headers(self):
        headers = self._config.create_headers()
        headers['IntegrationID'] = self._integration_id
        uuid = uuid4()
        headers['ArbitraryCode'] = str(uuid)
        try:
            headers['EncArbitraryCode'] = b64encode(rsa_encrypt(self._public_key, uuid.bytes)).decode('utf-8')
        except Exception as e:
            logger.error(f"خطا در رمزنگاری RSA: {str(e)}")
            raise Exception(f"خطا در تولید هدر رمزنگاری: {str(e)}")
        return headers