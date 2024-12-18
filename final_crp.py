from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.core.clipboard import Clipboard
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class GradientBackground(BoxLayout):
    def __init__(self, **kwargs):
        super(GradientBackground, self).__init__(**kwargs)
        with self.canvas.before:
            from kivy.graphics import Color, Rectangle
            Color(0.2, 0.6, 0.8, 1)  # Top color
            self.rect_top = Rectangle(size=self.size, pos=self.pos)
            Color(0.1, 0.4, 0.6, 1)  # Bottom color
            self.rect_bottom = Rectangle(size=self.size, pos=self.pos)

        self.bind(size=self.update_rect, pos=self.update_rect)

    def update_rect(self, *args):
        self.rect_top.size = self.size
        self.rect_bottom.size = self.size
        self.rect_bottom.pos = self.pos[0], self.pos[1] - self.height / 2

class MyApp(App):
    def build(self):
        # Create the main layout
        self.main_layout = GradientBackground(orientation='vertical', spacing=10, size_hint_y=None)
        self.main_layout = GridLayout(cols=1, spacing=10, size_hint_y=None)
        self.main_layout.bind(minimum_height=self.main_layout.setter('height'))

        # Build each cryptographic section
        self.build_caesar_cipher_section()
        self.build_binary_section()
        self.build_base64_section()
        self.build_rsa_section()
        self.build_vigenere_section()

        # Download button
        self.download_button = Button(text="Download Report", size_hint_y=None, height=50)
        self.download_button.bind(on_press=self.save_pdf_report)
        self.main_layout.add_widget(self.download_button)

        # ScrollView to make sure the content is scrollable
        scroll_view = ScrollView(size_hint=(1, 1))
        scroll_view.add_widget(self.main_layout)

        return scroll_view

    def build_caesar_cipher_section(self):
        caesar_label = Label(text="Caesar Cipher Encryption/Decryption", size_hint_y=None, height=50)
        self.main_layout.add_widget(caesar_label)

        self.caesar_message_input = TextInput(hint_text="Enter message", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.caesar_message_input)

        self.caesar_shift_input = TextInput(hint_text="Enter shift (key) value", size_hint_y=None, height=50, input_filter='int')
        self.main_layout.add_widget(self.caesar_shift_input)

        self.caesar_encode_button = Button(text="Encode", size_hint_y=None, height=50)
        self.caesar_encode_button.bind(on_press=self.caesar_encode)
        self.main_layout.add_widget(self.caesar_encode_button)

        self.caesar_decode_button = Button(text="Decode", size_hint_y=None, height=50)
        self.caesar_decode_button.bind(on_press=self.caesar_decode)
        self.main_layout.add_widget(self.caesar_decode_button)

        self.caesar_result_label = Label(text="Result will be displayed here", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.caesar_result_label)

        self.caesar_copy_button = Button(text="Copy Result", size_hint_y=None, height=50)
        self.caesar_copy_button.bind(on_press=self.copy_caesar_result)
        self.main_layout.add_widget(self.caesar_copy_button)

    def caesar_encode(self, instance):
        message = self.caesar_message_input.text
        shift_value = self.caesar_shift_input.text

        if not message or not shift_value:
            self.show_popup("Error", "Please enter both a message and a shift value.")
            return

        shift = int(shift_value)
        encoded_message = self.caesar_cipher(message, shift)
        self.caesar_result_label.text = f"Encoded Message: {encoded_message}"

    def caesar_decode(self, instance):
        message = self.caesar_message_input.text
        shift_value = self.caesar_shift_input.text

        if not message or not shift_value:
            self.show_popup("Error", "Please enter both a message and a shift value.")
            return

        shift = int(shift_value)
        decoded_message = self.caesar_cipher(message, -shift)
        self.caesar_result_label.text = f"Decoded Message: {decoded_message}"

    def copy_caesar_result(self, instance):
        result_text = self.caesar_result_label.text.split(": ")[1]
        Clipboard.copy(result_text)
        self.show_popup("Copied", f"Copied: {result_text}")

    def caesar_cipher(self, message, shift):
        result = ""
        for char in message:
            if char.isalpha():
                shift_base = 65 if char.isupper() else 97
                result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            else:
                result += char
        return result

    def build_binary_section(self):
        binary_label = Label(text="Binary Encoding/Decoding", size_hint_y=None, height=50)
        self.main_layout.add_widget(binary_label)

        self.binary_message_input = TextInput(hint_text="Enter message", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.binary_message_input)

        self.binary_encode_button = Button(text="Encode to Binary", size_hint_y=None, height=50)
        self.binary_encode_button.bind(on_press=self.binary_encode)
        self.main_layout.add_widget(self.binary_encode_button)

        self.binary_decode_button = Button(text="Decode from Binary", size_hint_y=None, height=50)
        self.binary_decode_button.bind(on_press=self.binary_decode)
        self.main_layout.add_widget(self.binary_decode_button)

        self.binary_result_label = Label(text="Result will be displayed here", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.binary_result_label)

        self.binary_copy_button = Button(text="Copy Result", size_hint_y=None, height=50)
        self.binary_copy_button.bind(on_press=self.copy_binary_result)
        self.main_layout.add_widget(self.binary_copy_button)

    def binary_encode(self, instance):
        message = self.binary_message_input.text
        if not message:
            self.show_popup("Error", "Please enter a message to encode.")
            return

        encoded_message = ' '.join(format(ord(char), '08b') for char in message)
        self.binary_result_label.text = f"Encoded Message: {encoded_message}"

    def binary_decode(self, instance):
        binary_message = self.binary_message_input.text
        if not binary_message:
            self.show_popup("Error", "Please enter a binary message to decode.")
            return

        decoded_message = ''.join(chr(int(b, 2)) for b in binary_message.split())
        self.binary_result_label.text = f"Decoded Message: {decoded_message}"

    def copy_binary_result(self, instance):
        result_text = self.binary_result_label.text.split(": ")[1]
        Clipboard.copy(result_text)
        self.show_popup("Copied", f"Copied: {result_text}")

    def build_base64_section(self):
        base64_label = Label(text="Base64 Encoding/Decoding", size_hint_y=None, height=50)
        self.main_layout.add_widget(base64_label)

        self.base64_message_input = TextInput(hint_text="Enter message", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.base64_message_input)

        self.base64_encode_button = Button(text="Encode to Base64", size_hint_y=None, height=50)
        self.base64_encode_button.bind(on_press=self.base64_encode)
        self.main_layout.add_widget(self.base64_encode_button)

        self.base64_decode_button = Button(text="Decode from Base64", size_hint_y=None, height=50)
        self.base64_decode_button.bind(on_press=self.base64_decode)
        self.main_layout.add_widget(self.base64_decode_button)

        self.base64_result_label = Label(text="Result will be displayed here", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.base64_result_label)

        self.base64_copy_button = Button(text="Copy Result", size_hint_y=None, height=50)
        self.base64_copy_button.bind(on_press=self.copy_base64_result)
        self.main_layout.add_widget(self.base64_copy_button)

    def base64_encode(self, instance):
        message = self.base64_message_input.text
        if not message:
            self.show_popup("Error", "Please enter a message to encode.")
            return

        encoded_message = base64.b64encode(message.encode()).decode()
        self.base64_result_label.text = f"Encoded Message: {encoded_message}"

    def base64_decode(self, instance):
        encoded_message = self.base64_message_input.text
        if not encoded_message:
            self.show_popup("Error", "Please enter a Base64 encoded message to decode.")
            return

        decoded_message = base64.b64decode(encoded_message).decode()
        self.base64_result_label.text = f"Decoded Message: {decoded_message}"

    def copy_base64_result(self, instance):
        result_text = self.base64_result_label.text.split(": ")[1]
        Clipboard.copy(result_text)
        self.show_popup("Copied", f"Copied: {result_text}")

    def build_rsa_section(self):
        rsa_label = Label(text="RSA Encryption/Decryption", size_hint_y=None, height=50)
        self.main_layout.add_widget(rsa_label)

        self.rsa_message_input = TextInput(hint_text="Enter message", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.rsa_message_input)

        self.rsa_encode_button = Button(text="Encrypt", size_hint_y=None, height=50)
        self.rsa_encode_button.bind(on_press=self.rsa_encrypt)
        self.main_layout.add_widget(self.rsa_encode_button)

        self.rsa_decode_button = Button(text="Decrypt", size_hint_y=None, height=50)
        self.rsa_decode_button.bind(on_press=self.rsa_decrypt)
        self.main_layout.add_widget(self.rsa_decode_button)

        self.rsa_result_label = Label(text="Result will be displayed here", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.rsa_result_label)

        self.rsa_copy_button = Button(text="Copy Result", size_hint_y=None, height=50)
        self.rsa_copy_button.bind(on_press=self.copy_rsa_result)
        self.main_layout.add_widget(self.rsa_copy_button)

        # RSA key generation
        self.generate_rsa_keys()

    def generate_rsa_keys(self):
        # Generate RSA key pair (private and public keys)
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()

    def rsa_encrypt(self, instance):
        message = self.rsa_message_input.text
        if not message:
            self.show_popup("Error", "Please enter a message to encrypt.")
            return

        # Encrypt message using RSA public key
        cipher = PKCS1_OAEP.new(RSA.import_key(self.public_key))
        encrypted_message = cipher.encrypt(message.encode())
        self.rsa_result_label.text = f"Encrypted Message (hex): {encrypted_message.hex()}"

    def rsa_decrypt(self, instance):
        encrypted_message_hex = self.rsa_message_input.text
        if not encrypted_message_hex:
            self.show_popup("Error", "Please enter a hexadecimal encrypted message to decrypt.")
            return

        try:
            encrypted_message = bytes.fromhex(encrypted_message_hex)
            cipher = PKCS1_OAEP.new(RSA.import_key(self.private_key))
            decrypted_message = cipher.decrypt(encrypted_message)
            self.rsa_result_label.text = f"Decrypted Message: {decrypted_message.decode()}"
        except ValueError as e:
            self.show_popup("Error", "Decryption failed. Please check the input.")

    def copy_rsa_result(self, instance):
        result_text = self.rsa_result_label.text.split(": ")[1]
        Clipboard.copy(result_text)
        self.show_popup("Copied", f"Copied: {result_text}")

    def build_vigenere_section(self):
        vigenere_label = Label(text="Vigenere Cipher", size_hint_y=None, height=50)
        self.main_layout.add_widget(vigenere_label)

        self.vigenere_message_input = TextInput(hint_text="Enter message", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.vigenere_message_input)

        self.vigenere_key_input = TextInput(hint_text="Enter key", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.vigenere_key_input)

        self.vigenere_encode_button = Button(text="Encode", size_hint_y=None, height=50)
        self.vigenere_encode_button.bind(on_press=self.vigenere_encode)
        self.main_layout.add_widget(self.vigenere_encode_button)

        self.vigenere_decode_button = Button(text="Decode", size_hint_y=None, height=50)
        self.vigenere_decode_button.bind(on_press=self.vigenere_decode)
        self.main_layout.add_widget(self.vigenere_decode_button)

        self.vigenere_result_label = Label(text="Result will be displayed here", size_hint_y=None, height=50)
        self.main_layout.add_widget(self.vigenere_result_label)

        self.vigenere_copy_button = Button(text="Copy Result", size_hint_y=None, height=50)
        self.vigenere_copy_button.bind(on_press=self.copy_vigenere_result)
        self.main_layout.add_widget(self.vigenere_copy_button)

    def vigenere_encode(self, instance):
        message = self.vigenere_message_input.text
        key = self.vigenere_key_input.text

        if not message or not key:
            self.show_popup("Error", "Please enter both a message and a key.")
            return

        encoded_message = self.vigenere_cipher(message, key, encode=True)
        self.vigenere_result_label.text = f"Encoded Message: {encoded_message}"

    def vigenere_decode(self, instance):
        message = self.vigenere_message_input.text
        key = self.vigenere_key_input.text

        if not message or not key:
            self.show_popup("Error", "Please enter both a message and a key.")
            return

        decoded_message = self.vigenere_cipher(message, key, encode=False)
        self.vigenere_result_label.text = f"Decoded Message: {decoded_message}"

    def copy_vigenere_result(self, instance):
        result_text = self.vigenere_result_label.text.split(": ")[1]
        Clipboard.copy(result_text)
        self.show_popup("Copied", f"Copied: {result_text}")

    def vigenere_cipher(self, message, key, encode=True):
        key = key.lower()
        key_length = len(key)
        result = ""

        for i, char in enumerate(message):
            if char.isalpha():
                shift = ord(key[i % key_length]) - 97
                if not encode:
                    shift = -shift
                base = 65 if char.isupper() else 97
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char

        return result

    def save_pdf_report(self, instance):
        # Save all results in the report
        c = canvas.Canvas("cryptographic_report.pdf", pagesize=letter)
        width, height = letter

        y_position = height - 50

        # Caesar Cipher
        c.drawString(50, y_position, "1.) Caesar Cipher Technique")
        y_position -= 20
        c.drawString(50, y_position, f"Encoded Process:")
        y_position -= 15
        c.drawString(50, y_position, f"Enter the message: {self.caesar_message_input.text}")
        y_position -= 15
        c.drawString(50, y_position, f"Shift Key Value: {self.caesar_shift_input.text}")
        y_position -= 15
        c.drawString(50, y_position, f"Encoded Value: {self.caesar_result_label.text.split(': ')[1]}")
        y_position -= 20
        c.drawString(50, y_position, f"Decoded Process:")
        y_position -= 15
        c.drawString(50, y_position, f"Enter the message: {self.caesar_message_input.text}")
        y_position -= 15
        c.drawString(50, y_position, f"Shift Key Value: {self.caesar_shift_input.text}")
        y_position -= 15
        c.drawString(50, y_position, f"Decoded Value: {self.caesar_result_label.text.split(': ')[1]}")

        # Binary Encoding/Decoding
        y_position -= 20
        c.drawString(50, y_position, "2.) Binary Encoding/Decoding Technique")
        y_position -= 15
        c.drawString(50, y_position, f"Encoded Value: {self.binary_result_label.text.split(': ')[1]}")
        y_position -= 15
        c.drawString(50, y_position, f"Decoded Value: {self.binary_result_label.text.split(': ')[1]}")

        # Base64 Encoding/Decoding
        y_position -= 20
        c.drawString(50, y_position, "3.) Base64 Encoding/Decoding Technique")
        y_position -= 15
        c.drawString(50, y_position, f"Encoded Value: {self.base64_result_label.text.split(': ')[1]}")
        y_position -= 15
        c.drawString(50, y_position, f"Decoded Value: {self.base64_result_label.text.split(': ')[1]}")

        # RSA Encryption/Decryption
        y_position -= 20
        c.drawString(50, y_position, "4.) RSA Encryption/Decryption Technique")
        y_position -= 15
        c.drawString(50, y_position, f"Encrypted Value: {self.rsa_result_label.text.split(': ')[1]}")
        y_position -= 15
        c.drawString(50, y_position, f"Decrypted Value: {self.rsa_result_label.text.split(': ')[1]}")

        # Vigenere Cipher
        y_position -= 20
        c.drawString(50, y_position, "5.) Vigenere Cipher Technique")
        y_position -= 15
        c.drawString(50, y_position, f"Encrypted Value: {self.vigenere_result_label.text.split(': ')[1]}")
        y_position -= 15
        c.drawString(50, y_position, f"Decrypted Value: {self.vigenere_result_label.text.split(': ')[1]}")

        c.save()
        self.show_popup("Success", "Report saved successfully as 'cryptographic_report.pdf'.")

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(400, 200))
        popup.open()

if __name__ == "__main__":
    MyApp().run()
