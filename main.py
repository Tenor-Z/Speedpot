import tkinter as tk
from gui import HoneypotGUI  # Import HoneypotGUI from the gui.py module
from config import HOST, PORT  # Import the HOST and PORT from config.py
    
def main():
    root = tk.Tk()
    app = HoneypotGUI(root, HOST, PORT)  # Pass HOST and PORT as positional arguments
    root.mainloop()

if __name__ == '__main__':
    root = tk.Tk()
    app = HoneypotGUI(root, HOST, PORT)  # Pass HOST and PORT
    root.mainloop()
