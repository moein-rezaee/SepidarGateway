import requests
from UsersService import UserService
import logging

logger = logging.getLogger(__name__)

class StocksService:
    def __init__(self, user: UserService):
        self._user = user

    def get_stocks(self):
        headers = self._user.create_headers()
        url = self._user.get_absolute_url('/api/Stocks')
        try:
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            logger.info(f"پاسخ دریافت انبارها: کد وضعیت {response.status_code}, محتوا: {response.text}")
            if response.status_code in (200, 201):
                try:
                    stocks = response.json()
                    return stocks if isinstance(stocks, list) else []
                except ValueError as e:
                    logger.error(f"خطا در تجزیه JSON: {str(e)}, پاسخ: {response.text}")
                    raise Exception(f"پاسخ سرور JSON معتبر نیست: {response.text}")
            else:
                try:
                    error_message = response.json().get('Message', response.text)
                except ValueError:
                    error_message = response.text
                raise Exception(f"خطا در دریافت انبارها: {error_message}")
        except requests.RequestException as e:
            logger.error(f"خطا در اتصال به API: {str(e)}")
            raise Exception(f"خطا در اتصال به API: {str(e)}")