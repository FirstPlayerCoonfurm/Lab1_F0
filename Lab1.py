import re
import logging
import PySimpleGUI as sg

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
                login = sg.popup_get_text("Введите логин: ")

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
                login = sg.popup_get_text("Неверный логин. Введите логин: ")
            else:
                logging.info("Длина логина неверна")
                login = sg.popup_get_text("Неверная длина логина. Введите логин: ")

        except Exception as err:
            logging.error(err)
            login = sg.popup_get_text("Ошибка ввода логина. Введите логин: ")


def val_pass(password: str, conf_password: str) -> (str, str):
    while True:
        try:
            logging.info(f'Введён пароль: {password}')

            if len(password) != 7:
                logging.info("Неверная длина пароля")
                password = sg.popup_get_text("Неверная длина пароля. Введите пароль: ")
                continue

            password_reg1 = re.compile(r"[a-zA-Z]+")

            if re.match(password_reg1, password):
                logging.info("Пароль верен!")

                if password == conf_password:
                    # Логирование успешной регистрации
                    logging.info('Пароль подтверждён, регистрация удачна')
                    return "True", "Успешное подтверждение пароля"

                else:
                    # Логирование несовпадения паролей
                    logging.warning('Пароль не подтверждён, в регистрации отказано')
                    password = sg.popup_get_text("Пароли не совпадают. Введите пароль: ")
                    conf_password = sg.popup_get_text("Подтвердите пароль: ")
                    continue
            else:
                logging.info("Неверный формат пароля")
                password = sg.popup_get_text("Неверный формат пароля. Введите пароль: ")
                continue

        except Exception as err:
            logging.error(err)
            password = sg.popup_get_text("Ошибка введенного пароля. Введите пароль: ")
            conf_password = sg.popup_get_text("Подтвердите пароль: ")


def register():
    layout = [
        [sg.Text('Введите логин:'), sg.Input(key='login')],
        [sg.Text('Введите пароль:'), sg.Input(key='password', password_char='*')],
        [sg.Text('Подтвердите пароль:'), sg.Input(key='conf_password', password_char='*')],
        [sg.Button('Зарегистрироваться'), sg.Button('Отмена')]
    ]

    window = sg.Window('Регистрация', layout)

    while True:
        event, values = window.read()

        if event == sg.WINDOW_CLOSED or event == 'Отмена':
            break

        login = values['login']
        password = values['password']
        conf_password = values['conf_password']

        try:
            username_result, username_msg = val_username(login)
            pass_result, pass_msg = val_pass(password, conf_password)

            if username_result == "True" and pass_result == "True":
                sg.popup("Nice!", "Успешное выполнение")
                break
            else:
                if username_result == "True":
                    sg.popup("Error!", pass_msg)
                else:
                    sg.popup("Error!", username_msg)

        except:
            logging.error()
            sg.popup("Error!", "Ошибка выполнения программы")

    window.close()


if __name__ == '__main__':
    register()