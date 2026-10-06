import sys
import os

# Добавляем корневую директорию в PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.app import ModbusApp

def main():
    app = ModbusApp()
    app.mainloop()

if __name__ == "__main__":
    main()
