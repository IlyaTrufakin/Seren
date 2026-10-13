"""Four user-visible threat states; retain main module's internal codes."""
LEVEL_NAMES = {0: 'Нет тревоги', 1: 'Низкая', 2: 'Высокая', 4: 'Критическая'}
LEVEL_SCALE = 'four-states-v1'

def collapse_level(value):
    if type(value) is not int or value not in range(6):
        raise ValueError('Некорректный уровень тревоги')
    return {0:0, 1:1, 2:2, 3:2, 4:4, 5:4}[value]

def level_name(value):
    return LEVEL_NAMES[value]
