import re
import logging
import os


logging.basicConfig(
    filename='logger.log',  # Имя файла для записи логов
    level=logging.INFO,  # Уровень записываемых логов
    format='%(asctime)s - %(levelname)s - %(message)s'  # Формат записи логов
)

os.system('clear')

print("Добро пожаловать!\n\nПожалуйста зарегистрируйтесь введя указанные ниже данные")
print("\nВведите логин (Номер телефона, Email или имя пользователя): ")
username = input()

logging.info(f'Введён логин: {username}')

# Проверка логина
username_reg = re.compile(r"^\+?(\d[\d\-.\s]+)?(\([\d\-.\s]+\))?[\d\-.\s]+\d$|^([a-zA-Zа-яА-ЯЁё0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})$|^([a-zA-Zа-яА-ЯЁё_]+)$")

try:
    if username_reg.match(username):
        print("\n\nВведите пароль пользователя: ")
        pass_user = input()
        logging.info(f'Введён пароль: {pass_user}')
        print("\nПодтвердите пароль: ")
        confirm_pass = input()
        
        if pass_user == confirm_pass:
            print("\nВы успешно зарегистрированы!")
            # Логирование успешной регистрации
            logging.info('Пароль подтверждён, регистрация удачна')
        
        else:
            print("\nПароли не совпадают!")
            # Логирование несовпадения паролей
            logging.warning('Пароль не подтверждён, в регистрации отказано')
    
    else:
        print("\nНекорректный логин!")
        # Логирование некорректного логина
        logging.warning('Некорректный логин')

except Error_login:
    logging.warning('Ошибка введённых данных!')
