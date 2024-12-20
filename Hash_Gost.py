import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
import struct

# Константы ГОСТ 28147-89
BLOCK_SIZE = 8
KEY_SIZE = 32

# Таблица замен
table = [
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
    [15, 4, 2, 13, 1, 11, 10, 6, 7, 3, 9, 5, 0, 14, 12, 8],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
]

def gost_encrypt_block(left, right, key):
    temp_sum = (left + key) % (2 ** 32)
    substitution_result = 0
    for i in range(8):
        nibble = (temp_sum >> (4 * i)) & 0xF
        substitution_result |= table[i][nibble] << (4 * i)
    shifted_result = (substitution_result << 11) | (substitution_result >> 21)
    final_result = shifted_result & 0xFFFFFFFF
    return right ^ final_result

def gost_encrypted_block(block, keys):
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF
    for i in range(24):
        left, right = gost_encrypt_block(left, right, keys[i % 8]), left
    for i in range(8):
        left, right = gost_encrypt_block(left, right, keys[7 - i]), left
    return (right << 32) | left

def hash(data, key):
    """
    Функция для хэширования данных с использованием ГОСТ 28147-89.
    """
    key = struct.unpack('>8I', key)
    blocks = [int.from_bytes(data[i:i + BLOCK_SIZE], 'big') for i in range(0, len(data), BLOCK_SIZE)]
    hash_value = 0

    for block in blocks:
        hash_value = gost_encrypted_block(hash_value, key) ^ block

    return hash_value.to_bytes(BLOCK_SIZE, 'big')

class GOSTApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ГОСТ 28147-89 Хэширование')

        main_layout = QVBoxLayout()

        key_layout = QHBoxLayout()
        key_label = QLabel('Ключ (32 байта):')
        self.key_input = QLineEdit()
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_input)
        main_layout.addLayout(key_layout)

        self.data_input = QTextEdit()
        self.data_input.setPlaceholderText('Введите данные для хэширования')
        main_layout.addWidget(self.data_input)

        button_layout = QHBoxLayout()
        self.hash_button = QPushButton('Хэшировать')
        button_layout.addWidget(self.hash_button)
        main_layout.addLayout(button_layout)

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        main_layout.addWidget(self.result_output)

        self.setLayout(main_layout)

        self.hash_button.clicked.connect(self.hash)

    def hash(self):
        key = self.key_input.text().encode('utf-8')
        data = self.data_input.toPlainText().encode('utf-8')
        if len(key) != KEY_SIZE:
            self.result_output.setText('Ошибка: ключ должен быть длиной 32 байта')
            return
        hash_value = hash(data, key)
        self.result_output.setText(hash_value.hex())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = GOSTApp()
    ex.show()
    sys.exit(app.exec_())