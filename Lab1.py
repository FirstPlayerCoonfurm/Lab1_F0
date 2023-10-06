import re
import logging
import os
import unittest
from unittest import mock


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
            if len(login) >= 5:
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
            elif len(login) == 0:
                logging.info("Длина логина неверна")
                login = input("Неверная длина логина. Введите логин: ")
                return "False", "unsuccess"

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


class TestValidation(unittest.TestCase):
    def test_val_username_empty_login(self):
        with mock.patch('builtins.input', return_value=''):
            result = val_username('')
            self.assertEqual(result, ('False', 'unsuccess'))

    def test_val_username_valid_email(self):
        with mock.patch('builtins.input', return_value='test@example.com'):
            result = val_username('')
            self.assertEqual(result, ('True', 'success'))

    def test_val_username_valid_username(self):
        with mock.patch('builtins.input', return_value='username123'):
            result = val_username('')
            self.assertEqual(result, ('True', 'success'))

    def test_val_username_invalid_login(self):
        with mock.patch('builtins.input', side_effect=['invalidlogin', 'username123']):
            result = val_username('')
            self.assertEqual(result, ('True', 'success'))

    def test_val_username_exception(self):
        with mock.patch('builtins.input', side_effect=[Exception('Error'), 'username123']):
            result = val_username('')
            self.assertEqual(result, ('True', 'success'))

    def test_val_pass_valid_password(self):
        with mock.patch('builtins.input', return_value='password123'):
            result = val_pass('password123', 'password123')
            self.assertEqual(result, ('True', 'Успешное подтверждение пароля'))

    def test_val_pass_invalid_password(self):
        with mock.patch('builtins.input', side_effect=['abcdefg', 'password123', 'password123']):
            result = val_pass('', '')
            self.assertEqual(result, ('True', 'Успешное подтверждение пароля'))

    def test_val_pass_password_mismatch(self):
        with mock.patch('builtins.input', side_effect=['password123', 'differentpassword', 'password123']):
            result = val_pass('', '')
            self.assertEqual(result, ('False', 'Пароли не совпадают. Введите пароль: '))

    def test_val_pass_invalid_format(self):
        with mock.patch('builtins.input', side_effect=['1', 'password123', 'password123']):
            result = val_pass('', '')
            self.assertEqual(result, ('True', 'Успешное подтверждение пароля'))

    def test_val_pass_exception(self):
        with mock.patch('builtins.input', side_effect=[Exception('Error'), 'password123', 'password123']):
            result = val_pass('', '')
            self.assertEqual(result, ('True', 'Успешное подтверждение пароля'))


class TestRegister(unittest.TestCase):
    def test_register_successful(self):
        with mock.patch('builtins.input', side_effect=['username123', 'password123', 'password123']):
            result = register('', '', '')
            self.assertEqual(result, ('True', 'Успешное выполнение'))

    def test_register_failed_invalid_password(self):
        with mock.patch('builtins.input', side_effect=['username123', 'abc', 'abc']):
            result = register('', '', '')
            self.assertEqual(result, ('False', 'Неверная длина пароля'))

    def test_register_failed_invalid_username(self):
        with mock.patch('builtins.input', side_effect=['', 'password123', 'password123']):
            result = register('', '', '')
            self.assertEqual(result, ('False', 'Логин не может быть пустым'))

    def test_register_exception(self):
        with mock.patch('builtins.input', side_effect=[Exception('Error')]):
            result = register('', '', '')
            self.assertEqual(result, ('False', 'Ошибка выполнения программы'))


if __name__ == '__main__':
    unittest.main()
