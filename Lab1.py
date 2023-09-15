import re
import logging
import os


logging.basicConfig(
    filename='logger.log',  # Имя файла для записи логов
    level=logging.INFO,  # Уровень записываемых логов
    format='%(asctime)s - %(levelname)s - %(message)s'  # Формат записи логов
)
logging.getLogger().addHandler(logging.StreamHandler())


def val_username(login: str):
    try:
        username = login
        logging.info(f'Введён логин: {login}')
        username_reg = re.compile(r"^\+?(\d[\d\-.\s]+)?(\([\d\-.\s]+\))?[\d\-.\s]+\d$|^([a-zA-Zа-яА-ЯЁё0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})$|^([a-zA-Z0-9_]+)$")

        if username_reg.match(username):
            logging.info("username is correct!")
            return True, "success"

    except Exception as err:
        logging.error(err)
        return False, "Неверный логин"


def val_pass(password: str, conf_password: str):
    try:
        pass_user = password
        logging.info(f'Введён пароль: {password}')
        confirm_pass = conf_password

        if pass_user == confirm_pass:
            # Логирование успешной регистрации
            logging.info('Пароль подтверждён, регистрация удачна')
            return True, "Успешное подтверждение пароля"

        else:
            # Логирование несовпадения паролей
            logging.warning('Пароль не подтверждён, в регистрации отказано')
            return False, "Пароли не совпадают!"

    except Exception as err:
        logging.error(err)
        return False, "Ошибка введённых паролей!"


def register(login: str, password: str, conf_password: str) -> (str, str):
    try:
        username_result, username_msg = val_username(login)
        pass_result, pass_msg = val_pass(password, conf_password)
        
        if username_result and pass_result:
            return True, "Успешное выполнение"
        else:
            return False, "Ошибка валидации"

    except Exception as err:
        logging.error(err)
        return False, "Ошибка выполнения программы"


result = register(login=input("Введите логин: "), password=input("Введите пароль: "), conf_password=input("Подтвердите пароль: "))
if result[0]:
    print("Nice!")
else:
    print("Error!")
