import pyshark
import curses
from collections import defaultdict
import threading
import logging
import time
import re
from datetime import datetime

# Настройка логирования
logging.basicConfig(filename='dns_capture.log', level=logging.INFO, format='%(asctime)s - %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

# Словарь для хранения количества запросов к каждому домену
domain_counts = defaultdict(int)
last_query_time = {}

# Регулярное выражение для упрощения доменов до их основного домена
def simplify_domain(domain):
    match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})$', domain)
    return match.group(1) if match else domain

# Функция для инициализации цветов
def init_colors():
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    curses.init_pair(7, curses.COLOR_BLUE, curses.COLOR_BLACK)

# Функция для обновления и отображения количества запросов
def update_counts(stdscr, domain):
    simplified_domain = simplify_domain(domain)
    domain_counts[simplified_domain] += 1
    last_query_time[simplified_domain] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Очистка экрана и установка рамки
    stdscr.clear()
    stdscr.border(0)

    # Заголовок
    stdscr.attron(curses.color_pair(3))
    stdscr.addstr(1, 2, "DNS Query Counts By BlackGonza", curses.A_BOLD | curses.A_UNDERLINE)
    stdscr.attroff(curses.color_pair(3))
    stdscr.attron(curses.color_pair(2))
    stdscr.addstr(2, 2, "-" * 30)
    stdscr.attroff(curses.color_pair(2))

    # Статистика
    total_queries = sum(domain_counts.values())
    unique_domains = len(domain_counts)
    stdscr.attron(curses.color_pair(6))
    stdscr.addstr(3, 2, f"Total Queries: {total_queries} | Unique Domains: {unique_domains}")
    stdscr.attroff(curses.color_pair(6))

    # Отображение всех доменов с градиентной цветовой схемой и сортировкой
    sorted_domains = sorted(domain_counts.items(), key=lambda item: item[1], reverse=True)
    max_y, max_x = stdscr.getmaxyx()
    for i, (domain, count) in enumerate(sorted_domains[:max_y - 6], start=4):
        color_pair = 1 + (i % 6)
        progress_bar = ('#' * (count // 5))[:max_x - 35]  # Прогресс-бар
        stdscr.attron(curses.color_pair(color_pair))
        stdscr.addstr(i % (max_y - 6) + 4, 2, f"{domain}: {count} (Last: {last_query_time[domain]}) {progress_bar}")
        stdscr.attroff(curses.color_pair(color_pair))

    stdscr.refresh()

# Функция для обработки пакетов
def process_packet(packet, stdscr):
    try:
        if 'DNS' in packet:
            dns_layer = packet.dns

            # Обработка запросов DNS
            if hasattr(dns_layer, 'qry_name'):
                query = dns_layer.qry_name
                if query:
                    update_counts(stdscr, query)

    except AttributeError:
        # Игнорировать пакеты без ожидаемых полей
        pass

# Функция для записи сообщений в лог
def log_message(message):
    logging.info(message)

def capture_dns(interface, stdscr):
    try:
        # Создаем захватчик трафика
        capture = pyshark.LiveCapture(interface=interface, display_filter='dns')
        logging.info("Запуск захвата DNS-запросов. Нажмите Ctrl+C для остановки.")
        capture.apply_on_packets(lambda p: process_packet(p, stdscr))
    except Exception as e:
        logging.error(f"Ошибка захвата: {e}")

def main(stdscr):
    # Инициализация цветов
    init_colors()

    # Убедитесь, что интерфейс указан правильно
    interface = 'wlan0'  # Замените на ваш сетевой интерфейс
    
    # Запускаем захват в отдельном потоке для лучшей производительности
    capture_thread = threading.Thread(target=capture_dns, args=(interface, stdscr))
    capture_thread.start()

    try:
        while True:
            time.sleep(1)  # Ожидание 1 секунду для предотвращения излишней загрузки процессора
    except KeyboardInterrupt:
        logging.info("Завершение работы по запросу пользователя.")
        capture_thread.join()

if __name__ == "__main__":
    # Запуск curses
    curses.wrapper(main)
