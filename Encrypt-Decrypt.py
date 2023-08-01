import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox
from cryptography.fernet import Fernet

class FileEncryptDecryptApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Set up the main window properties
        self.setWindowTitle('File Encrypt/Decrypt App')
        self.setGeometry(100, 100, 400, 150)

        # Create UI elements: labels, line edits, buttons
        self.file_path_label = QLabel('File Path:')
        self.file_path_lineedit = QLineEdit()
        self.file_path_button = QPushButton('Select File', self)
        self.file_path_button.clicked.connect(self.select_file)

        self.password_label = QLabel('Password:')
        self.password_lineedit = QLineEdit()

        self.encrypt_button = QPushButton('Encrypt', self)
        self.encrypt_button.clicked.connect(self.encrypt_file)

        self.decrypt_button = QPushButton('Decrypt', self)
        self.decrypt_button.clicked.connect(self.decrypt_file)

        self.generate_key_button = QPushButton('Generate Fernet Key', self)
        self.generate_key_button.clicked.connect(self.generate_key)

        # Arrange UI elements in layouts
        layout = QVBoxLayout()

        path_layout = QHBoxLayout()
        path_layout.addWidget(self.file_path_label)
        path_layout.addWidget(self.file_path_lineedit)
        path_layout.addWidget(self.file_path_button)

        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_lineedit)
        password_layout.addWidget(self.generate_key_button)

        layout.addLayout(path_layout)
        layout.addLayout(password_layout)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)

        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def generate_key(self):
        # Generate a new Fernet key
        fernet_key = Fernet.generate_key()

        # Convert the bytes key to a string and display it in the password line edit
        fernet_key_str = fernet_key.decode()
        self.password_lineedit.setText(fernet_key_str)

    def select_file(self):
        # Open a file dialog for the user to select a file
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File to Encrypt/Decrypt')
        if file_path:
            self.file_path_lineedit.setText(file_path)

    def encrypt_file(self):
        # Get the file path and password from the line edits
        file_path = self.file_path_lineedit.text()
        password = self.password_lineedit.text()

        # Check if both file path and password are provided
        if not file_path or not password:
            QMessageBox.warning(self, 'Warning', 'Please provide both file path and password.')
            return

        try:
            # Read the file content
            with open(file_path, 'rb') as file:
                data = file.read()

            # Create a Fernet instance with the provided password
            fernet = Fernet(password.encode())

            # Encrypt the data
            encrypted_data = fernet.encrypt(data)

            # Save the encrypted data to a new file with '.enc' extension
            with open(file_path + '.enc', 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)

            QMessageBox.information(self, 'Success', 'File encrypted successfully.')

        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error while encrypting the file:\n{str(e)}')

    def decrypt_file(self):
        # Get the file path and password from the line edits
        file_path = self.file_path_lineedit.text()
        password = self.password_lineedit.text()

        # Check if both file path and password are provided
        if not file_path or not password:
            QMessageBox.warning(self, 'Warning', 'Please provide both file path and password.')
            return

        try:
            # Read the encrypted file content
            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            # Create a Fernet instance with the provided password
            fernet = Fernet(password.encode())

            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)

            # Save the decrypted data to a new file with '.dec' extension
            with open(file_path[:-4], 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            QMessageBox.information(self, 'Success', 'File decrypted successfully.')

        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error while decrypting the file:\n{str(e)}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FileEncryptDecryptApp()
    window.show()
    sys.exit(app.exec_())
