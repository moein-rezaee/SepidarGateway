# Python 3
import logging
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from Configuration import Configuration
from DevicesService import DevicesService
from UsersService import UserService
from ItemsService import ItemsService
from CustomersService import CustomersService
from InvoicesService import InvoicesService
from UnitsService import UnitsService
from StocksService import StocksService
from CurrenciesService import CurrenciesService
from SaleTypesService import SaleTypesService
from QuotationsService import QuotationsService
from CryptoHelper import aes_encrypt, aes_decrypt
from logging.handlers import RotatingFileHandler

# تنظیمات لاگ با پشتیبانی از UTF-8 و فایل چرخشی
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # سطح DEBUG برای جزئیات بیشتر
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler = RotatingFileHandler('sepidar.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# تنظیمات برای نمایش صحیح فارسی در کنسول
sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = 'http://192.168.150.21:7373'
GENERATION_VERSION = '110'
REGISTRATION_CODE = '10002095'
USERNAME = 'robat'
PASSWORD = '8975789757'

class SepidarApp:
    def __init__(self, root):
        self.root = root
        self.root.title("سپیدار API - مدیریت داده‌ها")
        self.root.geometry("1000x700")

        # ایجاد جلسه HTTP با تلاش مجدد
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))

        # ایجاد تب‌ها
        self.notebook = ttk.Notebook(root)
        self.tab_items = ttk.Frame(self.notebook)
        self.tab_customers = ttk.Frame(self.notebook)
        self.tab_invoices = ttk.Frame(self.notebook)
        self.tab_units = ttk.Frame(self.notebook)
        self.tab_stocks = ttk.Frame(self.notebook)
        self.tab_currencies = ttk.Frame(self.notebook)
        self.tab_sale_types = ttk.Frame(self.notebook)
        self.tab_quotations = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_items, text="کالاها")
        self.notebook.add(self.tab_customers, text="مشتریان")
        self.notebook.add(self.tab_invoices, text="فاکتورها")
        self.notebook.add(self.tab_units, text="واحدها")
        self.notebook.add(self.tab_stocks, text="انبارها")
        self.notebook.add(self.tab_currencies, text="ارزها")
        self.notebook.add(self.tab_sale_types, text="انواع فروش")
        self.notebook.add(self.tab_quotations, text="پیش‌فاکتورها")
        self.notebook.add(self.tab_logs, text="لاگ‌ها")
        self.notebook.pack(expand=True, fill="both")
        self.test_connection().
        # ویجت‌های تب کالاها
        self.items_tree = ttk.Treeview(self.tab_items, columns=("ID", "Title", "Price"), show="headings")
        self.items_tree.heading("ID", text="شناسه")
        self.items_tree.heading("Title", text="نام کالا")
        self.items_tree.heading("Price", text="قیمت")
        self.items_tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_items, text="تازه‌سازی کالاها", command=self.refresh_items).pack(pady=5)

        # ویجت‌های تب مشتریان
        self.customers_tree = ttk.Treeview(self.tab_customers, columns=("ID", "Title", "Code"), show="headings")
        self.customers_tree.heading("ID", text="شناسه")
        self.customers_tree.heading("Title", text="نام مشتری")
        self.customers_tree.heading("Code", text="کد")
        self.customers_tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_customers, text="تازه‌سازی مشتریان", command=self.refresh_customers).pack(pady=5)

        # ویجت‌های تب فاکتورها
        self.invoices_tree = ttk.Treeview(self.tab_invoices, columns=("ID", "CustomerRef", "Price"), show="headings")
        self.invoices_tree.heading("ID", text="شناسه")
        self.invoices_tree.heading("CustomerRef", text="مرجع مشتری")
        self.invoices_tree.heading("Price", text="قیمت")
        self.invoices_tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_invoices, text="تازه‌سازی فاکتورها", command=self.refresh_invoices).pack(pady=5)

        # ویجت‌های تب واحدها
        self.units_tree = ttk.Treeview(self.tab_units, columns=("ID", "Title"), show="headings")
        self.units_tree.heading("ID", text="شناسه")
        self.units_tree.heading("Title", text="نام واحد")
        self.units_tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_units, text="تازه‌سازی واحدها", command=self.refresh_units).pack(pady=5)

        # ویجت‌های تب انبارها
        self.stocks_tree = ttk.Treeview(self.tab_stocks, columns=("ID", "Title", "IsActive"), show="headings")
        self.stocks_tree.heading("ID", text="شناسه")
        self.stocks_tree.heading("Title", text="نام انبار")
        self.stocks_tree.heading("IsActive", text="فعال")
        self.stocks_tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_stocks, text="تازه‌سازی انبارها", command=self.refresh_stocks).pack(pady=5)

        # ویجت‌های تب ارزها
        self.currencies_tree = ttk.Treeview(self.tab_currencies, columns=("ID", "Title"), show="headings")
        self.currencies_tree.heading("ID", text="شناسه")
        self.currencies_tree.heading("Title", text="نام ارز")
        self.currencies_tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_currencies, text="تازه‌سازی ارزها", command=self.refresh_currencies).pack(pady=5)

        # ویجت‌های تب انواع فروش
        self.sale_types_tree = ttk.Treeview(self.tab_sale_types, columns=("ID", "Title"), show="headings")
        self.sale_types_tree.heading("ID", text="شناسه")
        self.sale_types_tree.heading("Title", text="نام نوع فروش")
        self.sale_types_tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_sale_types, text="تازه‌سازی انواع فروش", command=self.refresh_sale_types).pack(pady=5)

        # ویجت‌های تب پیش‌فاکتورها
        self.quotations_tree = ttk.Treeview(self.tab_quotations, columns=("ID", "CustomerRef", "Price"), show="headings")
        self.quotations_tree.heading("ID", text="شناسه")
        self.quotations_tree.heading("CustomerRef", text="مرجع مشتری")
        self.quotations_tree.heading("Price", text="قیمت")
        self.quotations_tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_quotations, text="تازه‌سازی پیش‌فاکتورها", command=self.refresh_quotations).pack(pady=5)

        # ویجت‌های تب لاگ‌ها
        self.log_text = scrolledtext.ScrolledText(self.tab_logs, height=20, font=("Arial", 12))
        self.log_text.pack(fill="both", expand=True)
        self.log_handler = TextHandler(self.log_text)
        self.log_handler.setFormatter(formatter)
        logger.addHandler(self.log_handler)

        # تنظیمات اولیه
        self.config = Configuration(BASE_URL, GENERATION_VERSION)
        self.device = None
        self.user = None
        self.item_service = None
        self.customer_service = None
        self.invoice_service = None
        self.unit_service = None
        self.stock_service = None
        self.currency_service = None
        self.sale_type_service = None
        self.quotation_service = None

        # شروع فرآیند
        self.root.after(100, self.initialize_services)

    def initialize_services(self):
        logger.info("شروع برنامه...")
        try:
            # تست اتصال
            if not self.test_connection():
                messagebox.showerror("خطا", "اتصال به سرور برقرار نشد. لطفاً تنظیمات شبکه را بررسی کنید.")
                logger.error("اتصال به سرور برقرار نشد.")
                self.log_text.insert(tk.END, "خطا: اتصال به سرور برقرار نشد.\n")
                return

            # تست رمزنگاری
            self.test_encryption()

            # ثبت دستگاه
            logger.info(f"ثبت دستگاه با کد: {REGISTRATION_CODE}")
            self.device = DevicesService(self.config, REGISTRATION_CODE)
            try:
                self.device.register()
                logger.info(f"نام دستگاه: {self.device.DeviceName}")
                self.log_text.insert(tk.END, f"نام دستگاه: {self.device.DeviceName}\n")
            except Exception as e:
                if "دستگاه در حال حاضر رجیستر شده است" in str(e):
                    logger.info("دستگاه قبلاً رجیستر شده است. ادامه فرآیند...")
                    self.log_text.insert(tk.END, "دستگاه قبلاً رجیستر شده است.\n")
                    # فرض می‌کنیم دستگاه ثبت‌شده نیازی به کلید عمومی جدید ندارد
                    self.device.DeviceName = "RegisteredDevice"
                else:
                    logger.error(f"خطا در ثبت دستگاه: {str(e)}")
                    self.log_text.insert(tk.END, f"خطا در ثبت دستگاه: {str(e)}\n")
                    messagebox.showerror("خطا", f"خطا در ثبت دستگاه: {str(e)}")
                    return

            # لاگین کاربر
            logger.info(f"لاگین کاربر: {USERNAME}")
            self.user = UserService(self.device)
            try:
                self.user.login(USERNAME, PASSWORD)
                logger.info(f"عنوان کاربر: {self.user.user_title}")
                self.log_text.insert(tk.END, f"عنوان کاربر: {self.user.user_title}\n")
            except Exception as e:
                logger.error(f"خطا در لاگین: {str(e)}")
                self.log_text.insert(tk.END, f"خطا در لاگین: {str(e)}\n")
                messagebox.showerror("خطا", f"خطا در لاگین: {str(e)}")
                return

            # تنظیم سرویس‌ها
            self.item_service = ItemsService(self.user)
            self.customer_service = CustomersService(self.user)
            self.invoice_service = InvoicesService(self.user)
            self.unit_service = UnitsService(self.user)
            self.stock_service = StocksService(self.user)
            self.currency_service = CurrenciesService(self.user)
            self.sale_type_service = SaleTypesService(self.user)
            self.quotation_service = QuotationsService(self.user)

            # دریافت اولیه داده‌ها
            self.refresh_all()

        except Exception as e:
            logger.error(f"خطا در مقداردهی اولیه: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در مقداردهی اولیه: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در مقداردهی اولیه: {str(e)}")

    def test_connection(self):
        try:
            response = self.session.get(BASE_URL, timeout=5, verify=False)
            logger.info(f"تست اتصال: کد وضعیت {response.status_code}, پاسخ: {response.text[:200]}")
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"خطا در تست اتصال: {str(e)}")
            return False

    def test_encryption(self):
        logger.info("شروع تست رمزنگاری...")
        try:
            key = REGISTRATION_CODE * 2
            test_text = "1000"
            encrypted = aes_encrypt(key, test_text)
            logger.info(f"داده رمزنگاری شده: {encrypted['cipher']}, IV: {encrypted['iv']}")
            decrypted = aes_decrypt(key, encrypted['cipher'], encrypted['iv']).decode('utf-8')
            logger.info(f"داده رمزگشایی شده: {decrypted}")
            if decrypted == test_text:
                logger.info("تست رمزنگاری با موفقیت انجام شد!")
                self.log_text.insert(tk.END, "تست رمزنگاری با موفقیت انجام شد!\n")
            else:
                logger.error("خطا در رمزنگاری: داده رمزگشایی شده با اصلی مطابقت ندارد")
        except Exception as e:
            logger.error(f"خطا در تست رمزنگاری: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در تست رمزنگاری: {str(e)}\n")

    def refresh_all(self):
        self.refresh_items()
        self.refresh_customers()
        self.refresh_invoices()
        self.refresh_units()
        self.refresh_stocks()
        self.refresh_currencies()
        self.refresh_sale_types()
        self.refresh_quotations()

    def refresh_items(self):
        try:
            logger.info("دریافت آیتم‌ها...")
            items = self.item_service.get_items()
            logger.info(f"تعداد آیتم‌ها دریافت‌شده: {len(items)}")
            for item in self.items_tree.get_children():
                self.items_tree.delete(item)
            for item in items:
                self.items_tree.insert("", tk.END, values=(
                    item.get('ItemID', 'N/A'),
                    item.get('Title', 'بدون نام'),
                    item.get('Price', 'N/A')
                ))
            self.log_text.insert(tk.END, f"تعداد کالاها: {len(items)}\n")
        except Exception as e:
            logger.error(f"خطا در دریافت آیتم‌ها: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در دریافت کالاها: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در دریافت کالاها: {str(e)}")

    def refresh_customers(self):
        try:
            logger.info("دریافت مشتریان...")
            customers = self.customer_service.get_customers()
            logger.info(f"تعداد مشتریان دریافت‌شده: {len(customers)}")
            for item in self.customers_tree.get_children():
                self.customers_tree.delete(item)
            for customer in customers:
                self.customers_tree.insert("", tk.END, values=(
                    customer.get('CustomerID', 'N/A'),
                    customer.get('Title', 'بدون نام'),
                    customer.get('Code', 'N/A')
                ))
            self.log_text.insert(tk.END, f"تعداد مشتریان: {len(customers)}\n")
        except Exception as e:
            logger.error(f"خطا در دریافت مشتریان: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در دریافت مشتریان: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در دریافت مشتریان: {str(e)}")

    def refresh_invoices(self):
        try:
            logger.info("دریافت فاکتورها...")
            invoices = self.invoice_service.get_invoices()
            logger.info(f"تعداد فاکتورها دریافت‌شده: {len(invoices)}")
            for item in self.invoices_tree.get_children():
                self.invoices_tree.delete(item)
            for invoice in invoices:
                self.invoices_tree.insert("", tk.END, values=(
                    invoice.get('InvoiceID', 'N/A'),
                    invoice.get('CustomerRef', 'N/A'),
                    invoice.get('Price', 'N/A')
                ))
            self.log_text.insert(tk.END, f"تعداد فاکتورها: {len(invoices)}\n")
        except Exception as e:
            logger.error(f"خطا در دریافت فاکتورها: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در دریافت فاکتورها: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در دریافت فاکتورها: {str(e)}")

    def refresh_units(self):
        try:
            logger.info("دریافت واحدها...")
            units = self.unit_service.get_units()
            logger.info(f"تعداد واحدها دریافت‌شده: {len(units)}")
            for item in self.units_tree.get_children():
                self.units_tree.delete(item)
            for unit in units:
                self.units_tree.insert("", tk.END, values=(
                    unit.get('UnitID', 'N/A'),
                    unit.get('Title', 'بدون نام')
                ))
            self.log_text.insert(tk.END, f"تعداد واحدها: {len(units)}\n")
        except Exception as e:
            logger.error(f"خطا در دریافت واحدها: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در دریافت واحدها: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در دریافت واحدها: {str(e)}")

    def refresh_stocks(self):
        try:
            logger.info("دریافت انبارها...")
            stocks = self.stock_service.get_stocks()
            logger.info(f"تعداد انبارها دریافت‌شده: {len(stocks)}")
            for item in self.stocks_tree.get_children():
                self.stocks_tree.delete(item)
            for stock in stocks:
                self.stocks_tree.insert("", tk.END, values=(
                    stock.get('StockID', 'N/A'),
                    stock.get('Title', 'بدون نام'),
                    stock.get('IsActive', 'N/A')
                ))
            self.log_text.insert(tk.END, f"تعداد انبارها: {len(stocks)}\n")
        except Exception as e:
            logger.error(f"خطا در دریافت انبارها: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در دریافت انبارها: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در دریافت انبارها: {str(e)}")

    def refresh_currencies(self):
        try:
            logger.info("دریافت ارزها...")
            currencies = self.currency_service.get_currencies()
            logger.info(f"تعداد ارزها دریافت‌شده: {len(currencies)}")
            for item in self.currencies_tree.get_children():
                self.currencies_tree.delete(item)
            for currency in currencies:
                self.currencies_tree.insert("", tk.END, values=(
                    currency.get('CurrencyID', 'N/A'),
                    currency.get('Title', 'بدون نام')
                ))
            self.log_text.insert(tk.END, f"تعداد ارزها: {len(currencies)}\n")
        except Exception as e:
            logger.error(f"خطا در دریافت ارزها: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در دریافت ارزها: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در دریافت ارزها: {str(e)}")

    def refresh_sale_types(self):
        try:
            logger.info("دریافت انواع فروش...")
            sale_types = self.sale_type_service.get_sale_types()
            logger.info(f"تعداد انواع فروش دریافت‌شده: {len(sale_types)}")
            for item in self.sale_types_tree.get_children():
                self.sale_types_tree.delete(item)
            for sale_type in sale_types:
                self.sale_types_tree.insert("", tk.END, values=(
                    sale_type.get('SaleTypeID', 'N/A'),
                    sale_type.get('Title', 'بدون نام')
                ))
            self.log_text.insert(tk.END, f"تعداد انواع فروش: {len(sale_types)}\n")
        except Exception as e:
            logger.error(f"خطا در دریافت انواع فروش: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در دریافت انواع فروش: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در دریافت انواع فروش: {str(e)}")

    def refresh_quotations(self):
        try:
            logger.info("دریافت پیش‌فاکتورها...")
            quotations = self.quotation_service.get_quotations()
            logger.info(f"تعداد پیش‌فاکتورها دریافت‌شده: {len(quotations)}")
            for item in self.quotations_tree.get_children():
                self.quotations_tree.delete(item)
            for quotation in quotations:
                self.quotations_tree.insert("", tk.END, values=(
                    quotation.get('ID', 'N/A'),
                    quotation.get('CustomerRef', 'N/A'),
                    quotation.get('Price', 'N/A')
                ))
            self.log_text.insert(tk.END, f"تعداد پیش‌فاکتورها: {len(quotations)}\n")
        except Exception as e:
            logger.error(f"خطا در دریافت پیش‌فاکتورها: {str(e)}")
            self.log_text.insert(tk.END, f"خطا در دریافت پیش‌فاکتورها: {str(e)}\n")
            messagebox.showerror("خطا", f"خطا در دریافت پیش‌فاکتورها: {str(e)}")

class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.insert(tk.END, msg + '\n')
        self.text_widget.see(tk.END)

def main():
    root = tk.Tk()
    app = SepidarApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()