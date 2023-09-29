import unittest
from unittest.mock import patch
import logging
import re


logging.basicConfig(
    filename='logger.log',  # Имя файла для записи логов
    level=logging.INFO,  # Уровень записываемых логов
    format='%(asctime)s - %(levelname)s - %(message)s'  # Формат записи логов
)
logging.getLogger().addHandler(logging.StreamHandler())


def val_username(login: str) -> (str, str):
    while True:
        try:
            if not login:
                logging.info("Логин не может быть пустым")
                login = input("Введите логин: ")

            logging.info(f'Введён логин: {login}')
            if len(login) == 5:
                logging.info("Корректная длина логина")

                if re.match(r"^\+?(\d[\d\-.\s]+)?(\([\d\-.\s]+\))?[\d\-.\s]+\d$", login):
                    logging.info("Имя пользователя верно!")
                    return "True", "success"

                if re.match(r"^([a-zA-Zа-яА-ЯЁё0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})$", login):
                    logging.info("Имя пользователя верно!")
                    return "True", "success"

                if re.match(r"^([a-zA-Z0-9_]+)$", login):
                    logging.info("Имя пользователя верно!")
                    return "True", "success"

                logging.info("Неверный логин")
                login = input("Неверный логин. Введите логин: ")
            else:
                logging.info("Длина логина неверна")
                login = input("Неверная длина логина. Введите логин: ")

        except Exception as err:
            logging.error(err)
            login = input("Ошибка ввода логина. Введите логин: ")


def val_pass(password: str, conf_password: str) -> (str, str):
    while True:
        try:
            logging.info(f'Введён пароль: {password}')

            if len(password) <= 7:
                logging.info("Неверная длина пароля")
                password = input("Неверная длина пароля. Введите пароль: \n")
                continue

            password_reg1 = re.compile(r"[a-zA-Z0-9]+")

            if re.match(password_reg1, password):
                logging.info("Пароль верен!")

                if password == conf_password:
                    # Логирование успешной регистрации
                    logging.info('Пароль подтверждён, регистрация удачна')
                    return "True", "Успешное подтверждение пароля"

                else:
                    # Логирование несовпадения паролей
                    logging.warning('Пароль не подтверждён, в регистрации отказано')
                    password = input("Пароли не совпадают. Введите пароль: ")
                    conf_password = input("Подтвердите пароль: ")
                    continue
            else:
                logging.info("Неверный формат пароля")
                password = input("Неверный формат пароля. Введите пароль: \n")
                continue

        except Exception as err:
            logging.error(err)
            password = input("Ошибка введенного пароля. Введите пароль: ")
            conf_password = input("Подтвердите пароль: ")


def register(login: str, password: str, conf_password: str) -> (str, str):
    try:
        username_result, username_msg = val_username(login)
        pass_result, pass_msg = val_pass(password, conf_password)

        if username_result == "True" and pass_result == "True":
            return "True", "Успешное выполнение"
        else:
            if username_result == "True":
                return "False", pass_msg
            else:
                return "False", username_msg


    except:
        logging.error()
        return "False", "Ошибка выполнения программы"


result = register(
    login=input("Введите логин: "),
    password=input("Введите пароль: "),
    conf_password=input("Подтвердите пароль: ")
)

if result[0] == "True":
    print("Nice!", result[1])
else:
    print("Error!", result[1])


class TestRegistration(unittest.TestCase):
    def setUp(self):
        # Настройка логирования
        self.logger = logging.getLogger()
        self.logger.disabled = True

    def tearDown(self):
        # Восстановление логирования после каждого теста
        self.logger.disabled = False

    def test_registration_successful(self):
        result = register("username", "password1", "password1")
        self.assertEqual(result, ("True", "Успешное выполнение"))

    def test_empty_login(self):
        with patch('builtins.input', return_value=""):
            result = register("", "password1", "password1")
        self.assertEqual(result, ("False", "Логин не может быть пустым"))

    def test_valid_phone_login(self):
        with patch('builtins.input', return_value="+1234567890"):
            result = register("+1234567890", "password1", "password1")
        self.assertEqual(result, ("True", "Успешное выполнение"))

    def test_invalid_phone_login(self):
        with patch('builtins.input', side_effect=["+123", "+1234", "+12345", "+123456789012345"]):
            result = register("", "password1", "password1")
        self.assertEqual(result, ("False", "Неверная длина логина"))

    def test_valid_email_login(self):
        with patch('builtins.input', return_value="test@example.com"):
            result = register("test@example.com", "password1", "password1")
        self.assertEqual(result, ("True", "Успешное выполнение"))

    def test_invalid_email_login(self):
        with patch('builtins.input', return_value="invalid-email"):
            result = register("invalid-email", "password1", "password1")
        self.assertEqual(result, ("False", "Неверный логин"))

    def test_valid_username_login(self):
        with patch('builtins.input', return_value="username"):
            result = register("username", "password1", "password1")
        self.assertEqual(result, ("True", "Успешное выполнение"))

    def test_invalid_username_login(self):
        with patch('builtins.input', return_value="username#!"):
            result = register("username#!", "password1", "password1")
        self.assertEqual(result, ("False", "Неверный логин"))

    def test_short_password(self):
        with patch('builtins.input', return_value="short"):
            result = register("username", "short", "short")
        self.assertEqual(result, ("False", "Неверная длина пароля"))

    def test_valid_password(self):
        with patch('builtins.input', return_value="password1"):
            result = register("username", "password1", "password1")
        self.assertEqual(result, ("True", "Успешное выполнение"))

    def test_invalid_password(self):
        with patch('builtins.input', return_value="!@#$%^"):
            result = register("username", "!@#$%^", "!@#$%^")
        self.assertEqual(result, ("False", "Неверный формат пароля"))

    def test_password_mismatch(self):
        with patch('builtins.input', side_effect=["password1", "password2"]):
            result = register("username", "password1", "password2")
        self.assertEqual(result, ("False", "Пароли не совпадают"))

    def test_input_error(self):
        with patch('builtins.input', side_effect=Exception("Input error")):
            result = register("username", "password1", "password1")
        self.assertEqual(result, ("False", "Ошибка выполнения программы"))


if __name__ == '__main__':
    unittest.main()
